.PHONY: test-evidence-regressions
test-evidence-regressions:
	$(UV) run --locked python -m redteam.evidence_regressions
