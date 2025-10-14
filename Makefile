.PHONY: help all validate validate-all generate generate-python generate-go generate-typescript test test-all test-python clean clean-all bump-version

# Default target
help:
	@echo "Pentagi Taxonomy Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all VERSION=N            - Run full cycle: validate → generate → test"
	@echo "  validate VERSION=N       - Validate YAML schema for version N"
	@echo "  validate-all             - Validate all version schemas"
	@echo "  generate VERSION=N       - Generate code for all languages (version N)"
	@echo "  generate-python VERSION=N - Generate only Python code (version N)"
	@echo "  generate-go VERSION=N    - Generate only Go code (version N)"
	@echo "  generate-typescript VERSION=N - Generate only TypeScript code (version N)"
	@echo "  test VERSION=N           - Run Python tests for version N"
	@echo "  test-all                 - Run Python tests for all versions"
	@echo "  clean VERSION=N          - Remove generated files for version N"
	@echo "  clean-all                - Remove all generated files"
	@echo "  bump-version             - Create new major version directory"
	@echo ""
	@echo "Examples:"
	@echo "  make all VERSION=2       # Full cycle for v2"
	@echo "  make generate VERSION=2"
	@echo "  make test VERSION=1"
	@echo "  make validate-all"

# Full cycle: validate, generate, and test
all:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make all VERSION=N"; \
		exit 1; \
	fi
	@echo "Running full cycle for version $(VERSION)..."
	@echo ""
	@$(MAKE) validate VERSION=$(VERSION)
	@echo ""
	@$(MAKE) generate VERSION=$(VERSION)
	@echo ""
	@$(MAKE) test VERSION=$(VERSION)
	@echo ""
	@echo "✓ Full cycle complete for version $(VERSION)!"

# Validate schema for specific version
validate:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make validate VERSION=N"; \
		exit 1; \
	fi
	@echo "Validating schema for version $(VERSION)..."
	@python codegen/shared/validator.py v$(VERSION)/entities.yml

# Validate all version schemas
validate-all:
	@echo "Validating all schemas..."
	@for dir in v*/; do \
		if [ -f "$$dir/entities.yml" ]; then \
			echo "Validating $$dir..."; \
			python codegen/shared/validator.py "$$dir/entities.yml" || exit 1; \
		fi \
	done
	@echo "✓ All schemas validated successfully"

# Generate code for all languages (specific version)
generate: generate-python generate-go generate-typescript

# Generate Python code
generate-python:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make generate-python VERSION=N"; \
		exit 1; \
	fi
	@python codegen/python/generate.py $(VERSION)

# Generate Go code
generate-go:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make generate-go VERSION=N"; \
		exit 1; \
	fi
	@python codegen/go/generate.py $(VERSION)

# Generate TypeScript code
generate-typescript:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make generate-typescript VERSION=N"; \
		exit 1; \
	fi
	@python codegen/typescript/generate.py $(VERSION)

# Test specific version (Python package only)
test: test-python

# Test all versions
test-all:
	@echo "Running tests for all versions..."
	@for dir in v*/; do \
		if [ -f "$$dir/entities.yml" ]; then \
			version=$$(basename $$dir | sed 's/v//'); \
			echo "Testing version $$version..."; \
			$(MAKE) test VERSION=$$version || exit 1; \
		fi \
	done
	@echo "✓ All version tests passed"

# Test Python package
test-python:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make test-python VERSION=N"; \
		exit 1; \
	fi
	@echo "Testing Python package for version $(VERSION)..."
	@cd v$(VERSION)/python && python -m pytest tests/ -v

# Clean generated files for specific version
clean:
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is required. Usage: make clean VERSION=N"; \
		exit 1; \
	fi
	@echo "Cleaning generated files for version $(VERSION)..."
	@rm -rf v$(VERSION)/python/pentagi_taxonomy
	@rm -rf v$(VERSION)/go/entities
	@rm -rf v$(VERSION)/typescript/src
	@rm -rf v$(VERSION)/typescript/dist
	@rm -rf v$(VERSION)/typescript/node_modules
	@echo "✓ Cleaned version $(VERSION)"

# Clean all generated files
clean-all:
	@echo "Cleaning all generated files..."
	@for dir in v*/; do \
		if [ -f "$$dir/entities.yml" ]; then \
			version=$$(basename $$dir | sed 's/v//'); \
			echo "Cleaning version $$version..."; \
			$(MAKE) clean VERSION=$$version; \
		fi \
	done
	@echo "✓ All generated files cleaned"

# Bump to new major version
bump-version:
	@echo "Reading current version from version.yml..."
	@current=$$(grep 'version:' version.yml | awk '{print $$2}'); \
	new=$$((current + 1)); \
	echo "Current version: $$current"; \
	echo "New version: $$new"; \
	echo ""; \
	echo "Creating v$$new/ directory..."; \
	mkdir -p v$$new; \
	echo "Copying entities.yml from v$$current/ to v$$new/..."; \
	cp v$$current/entities.yml v$$new/entities.yml; \
	echo "Updating version field in v$$new/entities.yml..."; \
	sed -i.bak "s/^version: $$current/version: $$new/" v$$new/entities.yml && rm v$$new/entities.yml.bak; \
	echo "Updating version.yml to version $$new..."; \
	echo "# Current global taxonomy version" > version.yml; \
	echo "version: $$new" >> version.yml; \
	echo ""; \
	echo "✓ Created new version v$$new"; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Edit v$$new/entities.yml with your changes"; \
	echo "  2. Run: make validate VERSION=$$new"; \
	echo "  3. Run: make generate VERSION=$$new"; \
	echo "  4. Commit the new version"

