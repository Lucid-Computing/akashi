.PHONY: test-router demo-router
test-router:
	VIG_REQUIRE_ROUTER_ASSETS=1 $(UV) run --locked python -m unittest -v tests.test_mock_router tests.test_router_demo

demo-router:
	$(UV) run --locked python -m tests.router_demo
