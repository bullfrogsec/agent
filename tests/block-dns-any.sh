#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo mkdir -p /var/log/gha-agent

# Start the agent with dns-policy=any
sudo "$PROJECT_DIR/agent" \
  --egress-policy=block \
  --dns-policy=any \
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

# With dns-policy=any:
# - DNS queries to ANY domain should succeed
# - HTTP to non-allowed domains should still fail

# === HTTP Tests ===
echo "=== HTTP Tests ==="

if ! timeout 5 curl https://www.google.com --output /dev/null; then
  echo "Expected curl to www.google.com to succeed"
  exit 1
fi

if timeout 5 curl https://www.bing.com --output /dev/null; then
  echo "Expected curl to www.bing.com to fail (HTTP still blocked)"
  exit 1
fi

# === DNS Tests ===
echo "=== DNS Tests (dns-policy=any - all DNS should succeed) ==="

# DNS to any domain should succeed with dns-policy=any
if ! timeout 5 dig example.com; then
  echo "Expected dig example.com to succeed with dns-policy=any"
  exit 1
fi

if ! timeout 5 dig www.wikipedia.org; then
  echo "Expected dig www.wikipedia.org to succeed with dns-policy=any"
  exit 1
fi

if ! timeout 5 dig www.google.com; then
  echo "Expected dig www.google.com to succeed"
  exit 1
fi

echo ""
echo "================================================"
echo "Block + dns-any mode tests passed successfully!"
echo "================================================"