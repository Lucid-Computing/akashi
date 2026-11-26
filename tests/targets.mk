# An adjacent renderer checkout can supply the pinned runtime before #6 lands.
RENDERER_PROJECT ?= .

.PHONY: test-renderer-goldens

test-renderer-goldens:
	@set -eu; \
	: "$${AKASHI_RENDER_ASSETS:?set AKASHI_RENDER_ASSETS to the pinned tokenizer asset directory}"; \
	project=$$(cd "$(RENDERER_PROJECT)" && pwd); \
	PYTHONPATH="$$project:$$(pwd)" uv run --locked --project "$$project" python tests/test_render_goldens.py
