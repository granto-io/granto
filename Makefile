# Granto monorepo — delegates to module Makefiles.
# Extend with rbac/ targets as the module appears.

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: generate
generate: ## Run all generators in core
	$(MAKE) -C core generate

.PHONY: generate-wire
generate-wire: ## Wire only (core)
	$(MAKE) -C core generate-wire

.PHONY: generate-proto
generate-proto: ## Proto only (core)
	$(MAKE) -C core generate-proto

.PHONY: test
test: ## Test core
	$(MAKE) -C core test

.PHONY: test-consent
test-consent: ## Test consent
	$(MAKE) -C consent test

.PHONY: test-all
test-all: test test-consent ## Test core + consent

.PHONY: lint
lint: ## Lint core (golangci-lint)
	$(MAKE) -C core lint

.PHONY: lint-consent
lint-consent: ## Lint consent (golangci-lint)
	$(MAKE) -C consent lint

.PHONY: lint-all
lint-all: lint lint-consent ## Lint core + consent

.PHONY: lint-fix
lint-fix: ## Format + auto-fix core lint issues
	$(MAKE) -C core lint-fix

.PHONY: lint-fix-consent
lint-fix-consent: ## Format + auto-fix consent lint issues
	$(MAKE) -C consent lint-fix

.PHONY: install-hooks
install-hooks: ## Enable repo git hooks (.githooks/pre-commit → lint)
	git config core.hooksPath .githooks
	@chmod +x .githooks/pre-commit
	@echo "core.hooksPath=.githooks (pre-commit runs make lint on staged .go)"

.PHONY: build
build: ## Build core
	$(MAKE) -C core build

.PHONY: build-consent
build-consent: ## Build consent
	$(MAKE) -C consent build
