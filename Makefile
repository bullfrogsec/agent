.PHONY: build
build:
	docker build --tag agent-builder --build-arg BUILDOS=linux --build-arg BUILDARCH=amd64 .

	docker rm --force agent
	docker run --name agent agent-builder

	docker cp agent:/agent/agent .

.PHONY: fix
fix:
	go fmt ./...

# CI tests - Safe to run with bullfrog protection (uses mocks, no netfilter)
.PHONY: test.ci
test.ci: test.lint test.unit

# Integration tests - Require NO agent running (test real netfilter)
.PHONY: test.integration
test.integration: test.integration.block test.integration.audit test.integration.docker-block test.integration.block-dns-any test.integration.docker-escalation

.PHONY: test.integration.block
test.integration.block:
	bash tests/block.sh

.PHONY: test.integration.audit
test.integration.audit:
	bash tests/audit.sh

.PHONY: test.integration.docker-block
test.integration.docker-block:
	bash tests/docker-block.sh

# Runs on a real runner, where the `runner` account is in the docker group and
# /etc/sudoers.d/runner exists. Takes sudo away from the job, so it must be the
# last thing a job does.
.PHONY: test.integration.docker-escalation
test.integration.docker-escalation:
	bash tests/docker-escalation.sh

.PHONY: test.integration.block-dns-any
test.integration.block-dns-any:
	bash tests/block-dns-any.sh

# All tests - For local development with no agent running
.PHONY: test
test: test.ci test.integration

GOFMT_OUTPUT = $(shell gofmt -l .)

.PHONY: test.lint
test.lint:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "$$(gofmt -l .)"; \
		exit 1; \
	fi

.PHONY: test.unit
test.unit:
	go test ./...
