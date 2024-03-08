_regal:
	docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace \
		ghcr.io/styrainc/regal:latest \
		lint \
			--disable test-outside-test-package \
			--disable print-or-trace-call \
			--disable todo-comment \
			--disable no-defined-entrypoint pkg/auth/policies

.PHONY: lint
lint:
	docker pull ghcr.io/styrainc/regal:latest
	@$(MAKE) _regal

.PHONY: test
test: fmt
	opa check --v1-compatible --rego-v1 .
	opa test --v1-compatible -v .

.PHONY: fmt
fmt:
	opa fmt --v1-compatible --rego-v1 -w .
