.PHONY: test-telemetry

test-telemetry:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_telemetry tests.test_health
