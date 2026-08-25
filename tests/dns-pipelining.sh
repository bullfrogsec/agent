#!/bin/bash

set -e
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

sudo mkdir -p /var/log/gha-agent

# Built before the agent starts: once egress filtering is on, the module cache
# is unreachable, and a build failure would be indistinguishable from the
# behaviour under test.
DNSPIPELINE="$(mktemp -d)/dnspipeline"
(cd "$PROJECT_DIR" && go build -o "$DNSPIPELINE" ./tests/dnspipeline)

# 1.1.1.1 is allow-listed by IP so it is a trusted DNS server: the point of the
# test is the payload inspection, not the server check.
sudo "$PROJECT_DIR/agent" \
  --egress-policy=block \
  --dns-policy=allowed-domains-only \
  --allowed-domains="*.google.com" \
  --allowed-ips="1.1.1.1" \
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

# === DNS over TCP baseline ===
echo "=== DNS over TCP baseline ==="

if ! timeout 10 dig +tcp @1.1.1.1 www.google.com; then
  echo "Expected dig +tcp www.google.com to succeed, but it failed"
  exit 1
fi

if timeout 10 dig +tcp @1.1.1.1 example.com; then
  echo "Expected dig +tcp example.com to fail, but it succeeded"
  exit 1
fi

# === DNS pipelining ===
# Two queries in one TCP segment: an allowed domain in front of a blocked one.
# The tool exits non-zero if the blocked query was answered.
echo "=== DNS pipelining ==="

if ! "$DNSPIPELINE" \
  -server 1.1.1.1:53 \
  -allowed www.google.com \
  -blocked example.com; then
  echo "DNS pipelining bypassed egress filtering"
  exit 1
fi

echo ""
echo "=============================================="
echo "DNS pipelining tests passed successfully!"
echo "=============================================="
