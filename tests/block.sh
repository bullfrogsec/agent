#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo mkdir -p /var/log/gha-agent

# Start the agent
sudo "$PROJECT_DIR/agent" \
  --egress-policy=block \
  --dns-policy=allowed-domains-only \
  --allowed-domains="*.google.com" \
  --allowed-ips="1.1.1.1" \
  --enable-sudo=false \
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

# === HTTP Tests ===
echo "=== HTTP Tests ==="

if ! timeout 5 curl https://www.google.com --output /dev/null; then
  echo "Expected curl to www.google.com to succeed, but it failed"
  exit 1
fi

if timeout 5 curl https://www.bing.com --output /dev/null; then
  echo "Expected curl to www.bing.com to fail, but it succeeded"
  exit 1
fi

# === DNS Tests ===
echo "=== DNS Tests ==="

if timeout 5 dig example.com; then
  echo "Expected dig example.com to fail, but it succeeded"
  exit 1
fi

if ! timeout 5 dig www.google.com; then
  echo "Expected dig www.google.com to succeed, but it failed"
  exit 1
fi

if timeout 5 dig @8.8.8.8 www.google.com; then
  echo "Expected dig @8.8.8.8 www.google.com to fail (untrusted DNS), but it succeeded"
  exit 1
fi

if ! timeout 5 dig @1.1.1.1 www.google.com; then
  echo "Expected dig @1.1.1.1 www.google.com to succeed (allowed IP), but it failed"
  exit 1
fi

# === Sudo Tests ===
echo "=== Sudo Tests ==="

if sudo -n true 2>/dev/null; then
  echo "Expected sudo to fail, but it succeeded"
  exit 1
fi

echo ""
echo "=========================================="
echo "Block mode tests passed successfully!"
echo "=========================================="
