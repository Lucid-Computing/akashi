.PHONY: test-renderer

test-renderer:
	@set -eu; \
	if [ -z "$${VIG_RENDER_ASSETS:-}" ]; then \
		VIG_RENDER_ASSETS=$$(mktemp -d); export VIG_RENDER_ASSETS; \
		trap 'rm -f "$$VIG_RENDER_ASSETS/tokenizer.json" "$$VIG_RENDER_ASSETS/tokenizer_config.json"; rmdir "$$VIG_RENDER_ASSETS"' EXIT; \
		base='https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/resolve/86c5ecb6f2fbddf604c60120125fb202e09f2556'; \
		for file in tokenizer.json tokenizer_config.json; do \
			curl --fail --silent --show-error --location "$$base/$$file" --output "$$VIG_RENDER_ASSETS/$$file"; \
		done; \
	fi; \
	uv run --locked python -m unittest -v tests.test_renderer

.PHONY: test-request-policy

test-request-policy:
	uv run --no-project --python 3.13.18 python -m unittest -v tests.test_request_policy
