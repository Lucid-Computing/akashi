HAPROXY ?= haproxy
.PHONY: test-service-boundaries
test-service-boundaries:
	@command -v "$(HAPROXY)" >/dev/null || { echo "Set HAPROXY to the installed HAProxy executable" >&2; exit 1; }
	@command -v openssl >/dev/null && command -v node >/dev/null
	HAPROXY="$(HAPROXY)" uv run --no-project --python 3.13.18 python -m unittest -v tests.test_engine_proxy tests.test_service_roles tests.test_key_archive tests.test_publish_keys
