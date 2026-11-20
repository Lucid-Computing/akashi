.PHONY: test-receipts

test-receipts:
	uv run --locked python -m unittest -v tests.test_receipts

.PHONY: test-merkle-log

test-merkle-log:
	uv run --locked python -m unittest -v tests.test_merkle_vectors tests.test_log_store tests.test_log_http
