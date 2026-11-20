.PHONY: test-telemetry

test-telemetry:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_telemetry tests.test_health

.PHONY: test-private-operations
test-private-operations:
	$(UV) run --locked python -m unittest -v tests.test_private_operations
