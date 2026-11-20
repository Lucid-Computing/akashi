.PHONY: test-pickup-crypto
test-pickup-crypto:
	uv run --locked python -m unittest -v tests.test_pickup_crypto

.PHONY: test-pickup
test-pickup:
	$(UV) run --locked python -m unittest -v tests.test_pickup_crypto tests.test_pickup_store tests.test_pickup_http tests.test_delivery_commit
