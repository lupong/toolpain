PYTHON ?= python3.12
export PYTHONPATH := $(CURDIR)

.PHONY: dev test lint demo install install-prod env-detect bake-help

# Same recipe as Vultr scanner/control-plane installs (infra/install_toolpain.sh).
install:
	TOOLPAIN_PYTHON=$(PYTHON) TOOLPAIN_INSTALL_DEV=1 bash infra/install_toolpain.sh "$(CURDIR)"

install-prod:
	TOOLPAIN_PYTHON=$(PYTHON) TOOLPAIN_INSTALL_DEV=0 bash infra/install_toolpain.sh "$(CURDIR)"

env-detect:
	@$(PYTHON) -c "from control_plane.env_detect import detect; print(detect())"

dev:
	$(CURDIR)/.venv/bin/python -m uvicorn control_plane.main:app --reload --host 0.0.0.0 --port 8000

test:
	$(CURDIR)/.venv/bin/python -m pytest -q

lint:
	$(CURDIR)/.venv/bin/python -m ruff check .
	$(CURDIR)/.venv/bin/python -m ruff format --check .

demo:
	$(CURDIR)/.venv/bin/python -m runner.demo

bake-help:
	@bash infra/build-snapshot.sh
