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
  --allowed-domains="*.docker.io,docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com,production.cloudflare.docker.com,www.google.com" \
  --allowed-ips="172.17.0.0/16" \
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

# === Docker Container Tests ===
echo "=== Docker Container Tests ==="

# Test: curl from container to allowed domain should succeed
docker run --rm --entrypoint sh alpine/curl:8.7.1 -c "
    if ! timeout 5 curl https://www.google.com --output /dev/null; then
        echo 'Expected curl to www.google.com to succeed, but it failed';
        exit 1;
    fi;

    if timeout 5 curl https://www.bing.com --output /dev/null; then
        echo 'Expected curl to www.bing.com to fail, but it succeeded';
        exit 1;
    fi;
"

# Test: curl from different container version
docker run --rm --entrypoint sh alpine/curl:8.17.0 -c "
    if timeout 5 curl https://www.msn.com --output /dev/null; then
        echo 'Expected curl to www.msn.com to fail, but it succeeded';
        exit 1;
    fi;
"

# === Nginx Container Tests ===
echo "=== Nginx Container Tests ==="

CONTAINER_NAME=nginx-test-$$

# Start nginx container
docker run --detach --name $CONTAINER_NAME nginx:1.27

# Get container IP
NGINX_IP=$(docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_NAME)
echo "Nginx container IP: $NGINX_IP"

# Test: curl to nginx container should succeed (172.17.0.0/16 is allowed)
RETRIES=10
SUCCESS=false
for ((attempt = 1; attempt <= RETRIES; attempt++)); do
  echo "Attempt $attempt..."
  if curl --max-time 1 "http://$NGINX_IP" >/dev/null 2>&1; then
    echo "Successfully connected to nginx container."
    SUCCESS=true
    break
  fi
  sleep 1
done

# Cleanup
docker rm -f $CONTAINER_NAME >/dev/null 2>&1

if [ "$SUCCESS" != "true" ]; then
  echo "Failed to connect to nginx container"
  exit 1
fi

echo ""
echo "============================================="
echo "Docker block mode tests passed successfully!"
echo "============================================="