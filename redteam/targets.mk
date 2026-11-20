.PHONY: test-evidence-regressions
test-evidence-regressions:
	$(UV) run --locked python -m redteam.evidence_regressions

.PHONY: test-model-regressions
test-model-regressions:
	$(UV) run --locked python -m redteam.evidence_regressions --suite model

.PHONY: test-admission-regressions
test-admission-regressions:
	$(UV) run --locked python -m redteam.evidence_regressions --suite admission
