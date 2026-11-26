.PHONY: test-renderer

test-renderer:
	@set -eu; \
	if [ -z "$${AKASHI_RENDER_ASSETS:-}" ]; then \
		AKASHI_RENDER_ASSETS=$$(mktemp -d); export AKASHI_RENDER_ASSETS; \
		trap 'rm -f "$$AKASHI_RENDER_ASSETS/tokenizer.json" "$$AKASHI_RENDER_ASSETS/tokenizer_config.json"; rmdir "$$AKASHI_RENDER_ASSETS"' EXIT; \
		base='https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/resolve/86c5ecb6f2fbddf604c60120125fb202e09f2556'; \
		for file in tokenizer.json tokenizer_config.json; do \
			curl --fail --silent --show-error --location "$$base/$$file" --output "$$AKASHI_RENDER_ASSETS/$$file"; \
		done; \
	fi; \
	uv run --locked python -m unittest -v tests.test_renderer

.PHONY: test-request-policy

test-request-policy:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_request_policy

.PHONY: test-discovery

test-discovery:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_discovery

.PHONY: test-serving
test-serving:
	uv run --locked python -m unittest -v tests.test_serving tests.test_delivery_commit

.PHONY: test-streaming
test-streaming:
	AKASHI_REQUIRE_STREAM_ASSETS=1 $(UV) run --locked python -m unittest -v tests.test_streaming tests.test_stream_http
