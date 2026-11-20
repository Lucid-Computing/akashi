.PHONY: test-telemetry

test-telemetry:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_telemetry tests.test_health

.PHONY: test-operational-alerts
test-operational-alerts:
	$(UV) run --locked python -m unittest -v tests.test_operational_sources tests.test_operational_drills tests.test_health tests.test_log_monitor
	$(UV) run --locked python -m tools.operational_drills

.PHONY: test-private-operations
test-private-operations:
	$(UV) run --locked python -m unittest -v tests.test_private_operations
