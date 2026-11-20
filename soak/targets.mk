.PHONY: gate-m4
gate-m4:
	$(UV) run --locked python -m tools.gate_m4

.PHONY: test-m4
test-m4:
	$(UV) run --locked python -m unittest -v tests.test_soak_deployment tests.test_soak_holder tests.test_soak_gateway tests.test_soak_audit_service tests.test_soak_evidence
