.PHONY: test-proof-verification
test-proof-verification:
	$(UV) run --locked python -m unittest -v tests.test_proof_verification tests.test_lean_verifier

.PHONY: test-proof-verification-native
test-proof-verification-native:
	$(PYTHON) -m tests.native_verification $(VERIFY_ARGS)
