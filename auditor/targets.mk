.PHONY: test-beacon

test-beacon:
	uv run --locked python -m unittest -v tests.test_beacon
