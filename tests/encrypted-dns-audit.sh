#!/bin/bash

# Encrypted DNS (DoT / DoH) does not use port 53, so the agent never sees the
# query: it judges the connection on the resolver's IP alone. In audit mode
# nothing is blocked, so the queries succeed and the log records the resolver's
# IP with an "unknown" domain. The names actually looked up stay invisible.

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

LOG=/var/log/gha-agent/connections.log

sudo mkdir -p /var/log/gha-agent
sudo rm -f "$LOG"

sudo "$PROJECT_DIR/agent" \
  --egress-policy=audit \
  --dns-policy=allowed-domains-only \
  --allowed-domains="*.google.com" \
  --collect-process-info=true \
  &

# Wait for agent to be ready
TIMEOUT=30
COUNTER=0
while [ ! -f /var/run/bullfrog/agent-ready ] && [ $COUNTER -lt $TIMEOUT ]; do
  sleep 1
  COUNTER=$((COUNTER + 1))
done

if [ ! -f /var/run/bullfrog/agent-ready ]; then
  echo "Agent did not become ready within $TIMEOUT seconds"
  exit 1
fi

echo "Agent is ready, running tests..."

# The two names below are queried ONLY over the encrypted channels, so they
# must never appear as a domain in the log.
DOT_NAME=dot-probe.example.com
DOH_NAME=doh-probe.example.com

# === DNS-over-TLS ===
echo "=== DNS-over-TLS (port 853) ==="

if ! timeout 10 kdig +tls +timeout=3 @1.1.1.1 "$DOT_NAME"; then
  echo "Expected DoT query to 1.1.1.1:853 to succeed in audit mode, but it failed"
  exit 1
fi

# === DNS-over-HTTPS ===
echo "=== DNS-over-HTTPS (port 443) ==="

# Straight to the resolver's IP, so no plain DNS lookup happens first.
if ! timeout 10 curl --max-time 5 -sS -H 'accept: application/dns-json' \
  "https://1.1.1.1/dns-query?name=$DOH_NAME&type=A" --output /dev/null; then
  echo "Expected DoH request to 1.1.1.1 to succeed in audit mode, but it failed"
  exit 1
fi

# Give the agent a moment to flush the last connection log entry.
sleep 2

sudo cat "$LOG" > /tmp/connections.log

# === Log assertions ===
echo "=== Log assertions ==="

# Only the `domain` field is checked. The queried name also shows up in the
# logged command line of curl/kdig, which is not what monitoring reports on.
domains_for() {
  jq -r --arg ip "$1" --arg port "$2" \
    'select(.dstIP == $ip and .dstPort == $port) | .domain' /tmp/connections.log
}

dot_domains="$(domains_for 1.1.1.1 853)"
doh_domains="$(domains_for 1.1.1.1 443)"

if [ -z "$dot_domains" ]; then
  echo "Expected the DoT connection to 1.1.1.1:853 to be logged, but it was not"
  exit 1
fi

if [ -z "$doh_domains" ]; then
  echo "Expected the DoH connection to 1.1.1.1:443 to be logged, but it was not"
  exit 1
fi

# Every entry for the encrypted channels carries no domain: the agent only has
# the IP.
if [ -n "$(echo "$dot_domains" | grep -v '^unknown$' || true)" ]; then
  echo "Expected the DoT connection to be logged with an unknown domain, got: $dot_domains"
  exit 1
fi

if [ -n "$(echo "$doh_domains" | grep -v '^unknown$' || true)" ]; then
  echo "Expected the DoH connection to be logged with an unknown domain, got: $doh_domains"
  exit 1
fi

# The names looked up inside the encrypted sessions are nowhere in the log.
if jq -e -r --arg dot "$DOT_NAME" --arg doh "$DOH_NAME" \
  'select((.domain | test($dot)) or (.domain | test($doh)))' /tmp/connections.log; then
  echo "Expected the names queried over DoT/DoH to be invisible to the agent, but they were logged"
  exit 1
fi

# By contrast, a plain DNS query IS attributed to its domain.
timeout 5 dig www.google.com

sleep 2

sudo cat "$LOG"
sudo cat "$LOG" > /tmp/connections.log

if ! jq -e -r 'select(.domain == "www.google.com")' /tmp/connections.log > /dev/null; then
  echo "Expected the plain DNS query for www.google.com to be logged with its domain"
  exit 1
fi

echo ""
echo "==========================================================="
echo "Encrypted DNS audit mode tests passed successfully!"
echo "==========================================================="
