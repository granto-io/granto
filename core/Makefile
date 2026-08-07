# granto-core — common developer targets.
# Add new generators as generate-<name> and list them under generate.

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Code generation ────────────────────────────────────────

.PHONY: generate
generate: generate-wire generate-proto ## Run all code generators

.PHONY: generate-wire
generate-wire: ## Regenerate Google Wire (internal/di)
	go generate ./internal/di

.PHONY: generate-proto
generate-proto: ## Regenerate admin gRPC / gateway (api/admin → gen/admin)
	buf generate

# ── Build / test (extend as needed) ────────────────────────

.PHONY: test
test: ## Run unit tests
	go test ./... -count=1 -timeout 60s

.PHONY: build
build: ## Build granto-core binary
	go build -o bin/granto-core ./cmd
