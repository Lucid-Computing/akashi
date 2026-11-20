.PHONY: test-escrow
test-escrow:
	uv run --locked python -m unittest -v tests.test_escrow_crypto tests.test_escrow_store tests.test_escrow_sampler
