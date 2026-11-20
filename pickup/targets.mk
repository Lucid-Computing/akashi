.PHONY: test-pickup-crypto
test-pickup-crypto:
	uv run --locked python -m unittest -v tests.test_pickup_crypto
