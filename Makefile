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
test.integration: test.integration.block test.integration.audit test.integration.docker-block test.integration.block-dns-any

.PHONY: test.integration.block
test.integration.block:
	sudo bash tests/block.sh

.PHONY: test.integration.audit
test.integration.audit:
	sudo bash tests/audit.sh

.PHONY: test.integration.docker-block
test.integration.docker-block:
	sudo bash tests/docker-block.sh

.PHONY: test.integration.block-dns-any
test.integration.block-dns-any:
	sudo bash tests/block-dns-any.sh

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
