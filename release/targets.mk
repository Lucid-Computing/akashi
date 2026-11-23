.PHONY: release-check
release-check:
	$(UV) run --locked python -m release.check
