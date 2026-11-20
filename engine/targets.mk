PYTHON ?= python3

.PHONY: test-mock-engine verify-commitment

test-mock-engine:
	$(PYTHON) -m unittest -v tests.test_mock_engine

verify-commitment:
	@$(PYTHON) engine/verify_commitment.py
