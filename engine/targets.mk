PYTHON ?= python3

.PHONY: test-mock-engine

test-mock-engine:
	$(PYTHON) -m unittest -v tests.test_mock_engine
