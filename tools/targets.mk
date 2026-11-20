UV ?= uv

.PHONY: setup test-unit lint check-hardware

setup:
	$(UV) sync --locked

test-unit:
	$(UV) run --locked python -m unittest discover -v

lint:
	$(UV) run --locked python -m tools.check_pins
	$(UV) run --locked ruff check .
	$(UV) run --locked mypy .

check-hardware:
	$(UV) run --locked python -m tools.check_hardware

.PHONY: gate-m1
gate-m1:
	$(UV) run --locked python -m tools.gate_m1

.PHONY: docs-check
docs-check:
	$(UV) run --locked python -m tools.check_docs

.PHONY: gate-m0
gate-m0:
	$(UV) run --locked python -m tools.gate_m0
