# Granto monorepo — delegates to module Makefiles.
# Extend with consent/, rbac/ targets as modules appear.

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

.PHONY: build
build: ## Build core
	$(MAKE) -C core build
