.PHONY: test-telemetry

test-telemetry:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_telemetry tests.test_health

.PHONY: test-operational-alerts
test-operational-alerts:
	$(UV) run --locked python -m unittest -v tests.test_operational_sources tests.test_operational_drills tests.test_health tests.test_log_monitor
	$(UV) run --locked python -m tools.operational_drills

.PHONY: test-retention
test-retention:
	$(UV) run --locked python -m unittest -v tests.test_escrow_store tests.test_escrow_sampler tests.test_pickup_store tests.test_mailbox_retention tests.test_engine_logs tests.test_spool_retention tests.test_retention_cli tests.test_audit_retention tests.test_selected_retention
