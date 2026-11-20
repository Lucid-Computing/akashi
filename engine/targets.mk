PYTHON ?= python3

.PHONY: test-mock-engine

test-mock-engine:
	$(PYTHON) -m unittest -v tests.test_mock_engine

.PHONY: test-engine
test-engine:
	uv run --locked python -m unittest -v tests.test_engine_launch tests.test_engine_io tests.test_engine_adapter tests.test_engine_service tests.test_engine_control
