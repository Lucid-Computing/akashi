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
