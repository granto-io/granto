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
	GOWORK=off go generate ./internal/di

.PHONY: generate-proto
generate-proto: ## Regenerate admin gRPC / gateway (api/admin → gen/admin)
	buf generate

# ── Build / test (extend as needed) ────────────────────────

.PHONY: test
test: ## Run unit tests
	go test ./... -count=1 -timeout 60s

GOLANGCI_LINT_VERSION ?= v2.12.2
GOLANGCI_LINT ?= $(CURDIR)/bin/golangci-lint

.PHONY: lint
lint: $(GOLANGCI_LINT) ## Run golangci-lint (standard defaults)
	$(GOLANGCI_LINT) run ./...

.PHONY: lint-fix
lint-fix: $(GOLANGCI_LINT) ## Format + apply auto-fixes (gofmt / fixable linters)
	$(GOLANGCI_LINT) fmt ./...
	$(GOLANGCI_LINT) run --fix ./...

$(GOLANGCI_LINT):
	GOBIN=$(CURDIR)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: build
build: ## Build granto-core binary
	go build -o bin/granto-core ./cmd
