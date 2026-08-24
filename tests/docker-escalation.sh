#!/bin/bash

# --enable-sudo=false has to close BOTH routes to root on a runner: the sudoers
# file, and the docker group. The second one is not theoretical — the group is
# root-equivalent, because the daemon runs as root and mounts whatever it is
# asked to.
#
# This runs on a real GitHub runner rather than only in the e2e VM, because the
# things that make the vulnerability real are properties of the runner: the
# `runner` account is in the `docker` group, /etc/sudoers.d/runner exists, and
# the daemon is the host's own.
#
# It does NOT stop at the first failure. Run against an agent without the fix,
# a fail-fast script reports only that the fix is absent, which proves nothing
# about the checks themselves; run to the end, it reports WHICH escalations
# landed and that sudo came back — the evidence that these assertions have
# teeth. Environment problems are the exception and still abort: if the agent
# never started, nothing after it is a measurement of anything.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="${IMAGE:-alpine:3.20}"
# Written by a successful escalation. Deliberately in /etc rather than
# /etc/sudoers.d: this file has to be stat-able by the UNPRIVILEGED user for
# the check at the end to mean anything, and sudo is gone by then.
MARKER=/etc/bullfrog-escalation-poc
POC_VOLUME=bullfrog-poc-vol
POC_COPY=$(mktemp)
# The rule a successful escalation writes back. The reported proof of concept
# hardcodes "runner", which is this account on a GitHub runner; using the real
# account name keeps the final "sudo came back" check meaningful on any box,
# instead of quietly passing because the restored rule named someone else.
POC_SUDOERS="$(id -un) ALL=(ALL) NOPASSWD: ALL"

FAILURES=()
PASSED=0

# fatal is for the environment, not for the system under test: a fixture that
# is not in place makes every later check meaningless rather than failed.
fatal() {
  echo "ABORT: $*" >&2
  exit 2
}

# problem records a failed assertion and carries on.
problem() {
  FAILURES+=("$1")
  echo "  ✗ FAIL: $1"
}

pass() {
  PASSED=$((PASSED + 1))
  echo "  ✓ $1"
}

# A denial has to come from the policy. A command that fails because the image
# is missing, or docker is down, would otherwise read as a successful block —
# which is why "ordinary docker works" below is checked first and separately.
expect_denied() {
  local what="$1"
  shift
  local out
  if out=$("$@" 2>&1); then
    problem "$what SUCCEEDED — this is a bypass of --enable-sudo=false"
    [ -n "$out" ] && echo "        $(echo "$out" | head -3 | tr '\n' ' ')"
    return 0
  fi
  if [[ "$out" != *bullfrog* ]]; then
    problem "$what was refused, but not by bullfrog's policy: $(echo "$out" | head -2 | tr '\n' ' ')"
    return 0
  fi
  pass "denied: $what"
}

cleanup() {
  # The escalation vectors leave things behind when they succeed, which is
  # exactly when cleaning up matters: a leftover volume or marker would make
  # the next run report someone else's escalation.
  docker volume rm "$POC_VOLUME" >/dev/null 2>&1 || true
  rm -f "$POC_COPY"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Everything needing root happens BEFORE the agent starts. Taking sudo away is
# the point of the test, so there is no second chance to set anything up.
# ---------------------------------------------------------------------------
sudo mkdir -p /var/log/gha-agent
sudo rm -f "$MARKER"
# A readiness file left by an earlier run would be believed, and the test would
# proceed against an agent that never started — every assertion below then
# describes a box with no agent on it.
sudo rm -f /var/run/bullfrog/agent-ready
docker volume rm "$POC_VOLUME" >/dev/null 2>&1 || true
docker pull --quiet "$IMAGE"

# The fixture has to be real or the test proves nothing: an account that never
# had sudo, or never had docker, would pass every assertion below.
sudo -n true || fatal "this test needs passwordless sudo before the agent starts"
sudo test -f /etc/sudoers.d/runner || fatal "/etc/sudoers.d/runner is missing: this is not the environment under test"
id -nG | grep -qw docker || fatal "$(id -un) is not in the docker group: this is not the environment under test"

sudo "$PROJECT_DIR/agent" \
  --egress-policy=block \
  --dns-policy=allowed-domains-only \
  --allowed-domains="*.docker.io" \
  --enable-sudo=false \
  --collect-process-info=true \
  &

TIMEOUT=30
COUNTER=0
while [ ! -f /var/run/bullfrog/agent-ready ] && [ $COUNTER -lt $TIMEOUT ]; do
  sleep 1
  COUNTER=$((COUNTER + 1))
done
[ -f /var/run/bullfrog/agent-ready ] || fatal "the agent did not become ready within ${TIMEOUT}s"
# Readiness is a file; the agent writing it and then dying would leave the file
# behind and the test looking at an unprotected box.
# By process name, not by command line: a pgrep -f pattern also matches any
# wrapper whose own command line contains it, which would report a dead agent
# as alive — the exact false positive this check exists to catch.
pgrep -x agent >/dev/null || fatal "the agent is not running"

echo "=== Sudo is gone ==="
# Drop the cached credential first. Without this the check could pass on a
# timestamp earned before the agent started, which says nothing about whether
# sudo is still authorised.
sudo -k 2>/dev/null || true
if sudo -n true 2>/dev/null; then
  problem "sudo still works, so --enable-sudo=false did nothing"
else
  pass "sudo is refused"
fi

echo "=== Docker is still reachable by this account ==="
# The positive control for everything below, and it does not depend on the fix
# being present: unless an ordinary container runs, a refused escalation proves
# nothing — a runner with no docker would refuse them all.
DOCKER_USABLE=no
if out=$(docker run --rm "$IMAGE" echo bullfrog-ok 2>&1); then
  DOCKER_USABLE=yes
  pass "an ordinary container runs"
  # Not decoration: the fix relays a hijacked stream here, and a bug in that
  # path produces a container that runs, exits 0, and prints nothing.
  if [[ "$out" == *bullfrog-ok* ]]; then
    pass "its output comes back"
  else
    problem "the container ran but its output was lost: got '$out'"
  fi
else
  problem "an ordinary container could not run, so docker is unusable for this account: $(echo "$out" | head -2 | tr '\n' ' ')"
fi

# The other way to get a file into a container: create, copy, start. Both
# endpoints judge the target container's configuration as the daemon reports
# it, which is not the shape a client sends.
CP_CONTAINER=bullfrog-cp-$$
if out=$( { docker create --name "$CP_CONTAINER" "$IMAGE" cat /poc.txt &&
  echo bullfrog-copied >"$POC_COPY" &&
  docker cp "$POC_COPY" "$CP_CONTAINER:/poc.txt" &&
  docker start -a "$CP_CONTAINER"; } 2>&1); then
  if [[ "$out" == *bullfrog-copied* ]]; then
    pass "docker create, cp and start work"
  else
    problem "the copied file did not reach the container: got '$(echo "$out" | tail -2 | tr '\n' ' ')'"
  fi
else
  problem "docker create/cp/start was refused: $(echo "$out" | tail -2 | tr '\n' ' ')"
fi
docker rm -f "$CP_CONTAINER" >/dev/null 2>&1 || true

if out=$(docker run --rm --cap-drop ALL -m 64m "$IMAGE" id 2>&1); then
  pass "dropped capabilities and resource limits are allowed"
else
  problem "a container with dropped capabilities and a memory limit could not run: $(echo "$out" | head -2 | tr '\n' ' ')"
fi

echo "=== The daemon's API is filtered ==="
# The mechanism, reported rather than assumed. On its own it says only that the
# fix is installed, which is why it is one check among many rather than a gate
# in front of them.
if [ -S /var/run/docker.sock.bullfrog-real ]; then
  pass "the daemon's own socket was moved aside for the filter"
else
  problem "the daemon's socket was not moved aside: the filter is not installed"
fi
if [ -S /var/run/docker.sock ]; then
  pass "a socket is present at the path clients use"
else
  problem "no socket at the path clients use"
fi

echo "=== Escalation is refused ==="
if [ "$DOCKER_USABLE" = no ]; then
  echo "  (docker is unusable for this account, so the denials below prove nothing)"
fi

# The reported proof of concept, verbatim.
expect_denied "privileged container with the host root mounted" \
  docker run --rm --privileged -v /:/host "$IMAGE" sh -c "echo '$POC_SUDOERS' > /host/etc/sudoers.d/runner"

# Neither --privileged nor a mount of / is needed: one directory is enough.
expect_denied "bind mount of a single host directory" \
  docker run --rm -v /etc:/host "$IMAGE" sh -c "echo poc > /host/bullfrog-escalation-poc"

# Defeats a filter that only looks at bind mounts: the local volume driver
# takes a host path as a device option.
expect_denied "volume backed by a host path" \
  docker volume create -d local -o type=none -o device=/ -o o=bind "$POC_VOLUME"

# No mounts and no privileges at all: --net=host alone hands the container
# CAP_NET_RAW in the HOST network namespace, which is the raw-packet path
# around the egress filter that --enable-sudo=false exists to close.
expect_denied "host network namespace" \
  docker run --rm --net=host "$IMAGE" true

expect_denied "added capability" \
  docker run --rm --cap-add SYS_ADMIN "$IMAGE" true

expect_denied "host pid namespace" \
  docker run --rm --pid=host "$IMAGE" true

expect_denied "unconfined seccomp" \
  docker run --rm --security-opt seccomp=unconfined "$IMAGE" true

# Nothing obliges an attacker to use the docker CLI, so a control implemented
# in the client is not a control. This posts the container definition to the
# daemon's HTTP API by hand. --fail-with-body, not --fail: the exit status
# says it was refused, the body says who refused it, and this test needs both.
expect_denied "the same request, straight to the socket" \
  curl -sS --fail-with-body --unix-socket /var/run/docker.sock \
    -X POST -H "Content-Type: application/json" \
    -d "{\"Image\":\"$IMAGE\",\"HostConfig\":{\"Binds\":[\"/:/host\"]}}" \
    http://docker/containers/create

# Installing the filter means moving the daemon's own socket to another name,
# and a rename preserves the inode along with the group access it had. If that
# access is not taken away, `docker -H unix://<relocated socket>` reaches the
# unfiltered daemon and every denial above can be sidestepped with one flag.
# Refused here by file permissions rather than by the policy, so unlike the
# checks above this one does not look for a bullfrog message.
if [ -S /var/run/docker.sock.bullfrog-real ]; then
  if out=$(docker -H unix:///var/run/docker.sock.bullfrog-real run --rm --privileged       -v /:/host "$IMAGE" sh -c "echo poc > /host$MARKER" 2>&1); then
    problem "the daemon's relocated socket is still reachable, so the filter can be walked around"
  else
    pass "denied: connecting straight to the daemon's relocated socket"
  fi
else
  echo "  (no filter installed, so there is no relocated socket to reach)"
fi

# The daemon treats any run of digits and dots as an API version, so the same
# request can be spelled several ways. A filter that recognises a narrower
# shape forwards what it failed to parse, and the daemon routes it to the very
# endpoint that was meant to be judged.
for prefix in /v1.51 /v1.51.0 /v1.51. /v1; do
  expect_denied "the same request under $prefix" \
    curl -sS --fail-with-body --unix-socket /var/run/docker.sock \
      -X POST -H "Content-Type: application/json" \
      -d "{\"Image\":\"$IMAGE\",\"HostConfig\":{\"Privileged\":true,\"Binds\":[\"/:/host\"]}}" \
      "http://docker$prefix/containers/create"
done

# The daemon percent-decodes query values; a substring check on the raw query
# does not. networkmode=host runs every build step in the host network
# namespace as root.
expect_denied "a build in the host network, percent-encoded" \
  curl -sS --fail-with-body --unix-socket /var/run/docker.sock \
    -X POST "http://docker/build?networkmode=%68ost&t=bullfrog-poc"

echo "=== Nothing landed on the host ==="
# The assertions that actually matter. The exit codes above say the commands
# failed; these say the escalation did not happen.
if [ -e "$MARKER" ]; then
  problem "$MARKER was written: an escalation reached the host filesystem"
else
  pass "no file was written to the host"
fi
sudo -k 2>/dev/null || true
if sudo -n true 2>/dev/null; then
  problem "sudo works again, so the escalation succeeded end to end"
else
  pass "sudo is still refused"
fi

echo ""
echo "=========================================="
if [ ${#FAILURES[@]} -eq 0 ]; then
  echo "Docker escalation tests passed: $PASSED checks"
  echo "=========================================="
  exit 0
fi
echo "Docker escalation tests FAILED: ${#FAILURES[@]} of $((PASSED + ${#FAILURES[@]})) checks"
echo "=========================================="
for f in "${FAILURES[@]}"; do
  echo "  ✗ $f"
done
exit 1
