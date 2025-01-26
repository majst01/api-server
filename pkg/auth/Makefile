_regal:
	docker pull ghcr.io/styrainc/regal:latest
	docker run --rm \
		-v $(PWD):/workspace \
		-w /workspace \
		ghcr.io/styrainc/regal:latest \
		lint \
			--disable test-outside-test-package \
			--disable directory-package-mismatch \
			$(POLICIES_PATH)

_opa:
	docker run --rm \
		--user $$(id -u):$$(id -g) \
		-v $(PWD):/workspace \
		-w /workspace \
		openpolicyagent/opa:edge-static \
		$(CMD)

_test:
	@$(MAKE) _opa CMD="check --v1-compatible --rego-v1 $(POLICIES_PATH)"
	@$(MAKE) _opa CMD="test --var-values --v1-compatible -v $(POLICIES_PATH)"

.PHONY: lint
lint: fmt
	@$(MAKE) _regal POLICIES_PATH=authentication
	@$(MAKE) _regal POLICIES_PATH=authorization

.PHONY: test
test: fmt test-authentication test-authorization

.PHONY: test-authorization
test-authorization:
	$(MAKE) _test POLICIES_PATH=authorization

.PHONY: test-authentication
test-authentication:
	$(MAKE) _test POLICIES_PATH=authentication

.PHONY: fmt
fmt:
	docker pull openpolicyagent/opa:edge-static
	@$(MAKE) _opa CMD="fmt --v1-compatible --rego-v1 -w ."
