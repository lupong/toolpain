PYTHON ?= python3.12
export PYTHONPATH := $(CURDIR)

.PHONY: dev test lint demo install env-detect

install:
	$(PYTHON) -m pip install -e ".[dev]"

env-detect:
	@$(PYTHON) -c "from control_plane.env_detect import detect; print(detect())"

dev:
	$(PYTHON) -m uvicorn control_plane.main:app --reload --host 0.0.0.0 --port 8000

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

demo:
	$(PYTHON) -m runner.demo
