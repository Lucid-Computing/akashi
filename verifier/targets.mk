.PHONY: test-holder-verifier
test-holder-verifier:
	$(UV) run --locked python -m unittest -v tests.test_holder tests.test_holder_proof
