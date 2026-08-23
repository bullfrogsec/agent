#!/bin/bash

# Encrypted DNS (DoT / DoH) never reaches the DNS inspection path: it does not
# use port 53, so the agent judges it as an ordinary connection to the
# resolver's IP. In block mode that IP is not in the allow-list, so the
# connection is denied and the client never gets an answer.

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo mkdir -p /var/log/gha-agent

# Note: no --allowed-ips, so the resolver's IP is not allowed either.
sudo "$PROJECT_DIR/agent" \
  --egress-policy=block \
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

# === DNS-over-TLS ===
echo "=== DNS-over-TLS (port 853) ==="

if timeout 10 kdig +tls +timeout=3 @1.1.1.1 example.com; then
  echo "Expected DoT query to 1.1.1.1:853 to fail, but it succeeded"
  exit 1
fi

# === DNS-over-HTTPS ===
echo "=== DNS-over-HTTPS (port 443) ==="

# Straight to the resolver's IP, so no plain DNS lookup happens first.
if timeout 10 curl --max-time 5 -sS -H 'accept: application/dns-json' \
  'https://1.1.1.1/dns-query?name=example.com&type=A' --output /dev/null; then
  echo "Expected DoH request to 1.1.1.1 to fail, but it succeeded"
  exit 1
fi

# Resolving a DoH endpoint by name is blocked one step earlier, at the plain
# DNS query for the endpoint itself.
if timeout 10 dig +timeout=3 cloudflare-dns.com; then
  echo "Expected dig cloudflare-dns.com to fail, but it succeeded"
  exit 1
fi

# The allow-list still works over plain DNS, so this is a denial of encrypted
# DNS specifically and not the agent failing everything.
if ! timeout 5 curl https://www.google.com --output /dev/null; then
  echo "Expected curl to www.google.com to succeed, but it failed"
  exit 1
fi

echo ""
echo "==========================================================="
echo "Encrypted DNS block mode tests passed successfully!"
echo "==========================================================="
