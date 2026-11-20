PYTHON ?= python3

.PHONY: test-proof-request

test-proof-request:
	$(PYTHON) -m unittest -v tests.test_proof_request

.PHONY: test-mock-prover

test-mock-prover:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_mock_prover

.PHONY: test-proof-worker
test-proof-worker:
	uv run --locked python -m unittest -v tests.test_proof_submission tests.test_prover_runtime tests.test_proof_worker

.PHONY: test-proof-spool-native
test-proof-spool-native:
	$(PYTHON) -m tests.native_spool

REFERENCE_PYTHON ?= $(UV) run --locked python
.PHONY: test-reference-scorer
test-reference-scorer:
	$(REFERENCE_PYTHON) -m unittest -v tests.test_reference tests.test_scoring
