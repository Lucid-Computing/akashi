.PHONY: test-receipts

test-receipts:
	uv run --locked python -m unittest -v tests.test_receipts
