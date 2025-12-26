SHELL := /bin/bash

.PHONY: help push sync test hooks ci

help:
	@echo "Available targets:"
	@echo "  make push   - Stash → rebase (upstream/origin) → push → pop"
	@echo "  make sync   - Same as push (alias)"
	@echo "  make test   - Run test suite"
	@echo "  make hooks  - Install local Git hooks"
	@echo "  make ci     - Clean install + run tests (CI-style)"

hooks:
	@bash ./scripts/install-git-hooks.sh

push: hooks
	@bash ./scripts/git-sync.sh

sync: push

test:
	@npm test --silent

ci:
	@npm ci
	@npm test --silent

