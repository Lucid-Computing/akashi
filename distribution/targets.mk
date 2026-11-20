.PHONY: test-package
test-package:
	$(UV) run --locked python -m tools.package_verifier
