.PHONY: test-beacon

test-beacon:
	uv run --locked python -m unittest -v tests.test_beacon

.PHONY: test-selections
test-selections:
	uv run --locked python -m unittest -v tests.test_selection_record tests.test_selections

.PHONY: test-audit-jobs
test-audit-jobs:
	$(UV) run --locked python -m unittest -v tests.test_audit_jobs tests.test_sampled_jobs
