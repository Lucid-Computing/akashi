PYTHON ?= python3

.PHONY: test-mock-engine test-engine verify-commitment

test-mock-engine:
	$(PYTHON) -m unittest -v tests.test_mock_engine

test-engine:
	$(UV) run --locked python -m unittest -v tests.test_engine_launch tests.test_engine_io tests.test_engine_adapter tests.test_engine_service tests.test_engine_control

verify-commitment:
	@$(PYTHON) engine/verify_commitment.py
