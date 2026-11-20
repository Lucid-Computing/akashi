.PHONY: test-beacon

test-beacon:
	uv run --locked python -m unittest -v tests.test_beacon

.PHONY: test-selections
test-selections:
	uv run --locked python -m unittest -v tests.test_selection_record tests.test_selections

.PHONY: test-audit-api
test-audit-api:
	$(UV) run --locked python -m unittest -v tests.test_verdicts tests.test_verdict_http
