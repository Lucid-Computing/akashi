PYTHON ?= python3

.PHONY: test-proof-request

test-proof-request:
	$(PYTHON) -m unittest -v tests.test_proof_request

.PHONY: test-mock-prover

test-mock-prover:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_mock_prover
