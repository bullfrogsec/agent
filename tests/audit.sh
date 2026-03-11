#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo mkdir -p /var/log/gha-agent

# Start the agent in audit mode
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

# In audit mode, ALL requests should succeed (just logged, not blocked)

# === HTTP Tests ===
echo "=== HTTP Tests (audit mode - all should succeed) ==="

if ! timeout 5 curl https://www.google.com --output /dev/null; then
  echo "Expected curl to www.google.com to succeed"
  exit 1
fi

if ! timeout 5 curl https://www.bing.com --output /dev/null; then
  echo "Expected curl to www.bing.com to succeed in audit mode"
  exit 1
fi

# === DNS Tests ===
echo "=== DNS Tests (audit mode - all should succeed) ==="

# Even queries to "blocked" domains should succeed in audit mode
if ! timeout 5 dig example.com; then
  echo "Expected dig example.com to succeed in audit mode"
  exit 1
fi

if ! timeout 5 dig www.google.com; then
  echo "Expected dig www.google.com to succeed"
  exit 1
fi

# Queries to untrusted DNS servers should also succeed in audit mode
if ! timeout 5 dig @8.8.8.8 www.google.com; then
  echo "Expected dig @8.8.8.8 to succeed in audit mode"
  exit 1
fi

echo ""
echo "==========================================="
echo "Audit mode tests passed successfully!"
echo "==========================================="