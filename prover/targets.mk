PYTHON ?= python3

.PHONY: test-proof-request

test-proof-request:
	$(PYTHON) -m unittest -v tests.test_proof_request
