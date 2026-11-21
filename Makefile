.PHONY: setup lint test test-linux demo bench audit ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# Portable tests on a copy of the fixture host tree (Linux-only tests are deselected).
test:
	mkdir -p .tmp
	$(PY) -m pytest -q -rs $(PYTEST_ARGS)

# Real inotify, symlinks, FIFOs and unreadable directories (Linux only; CI runs this).
test-linux:
	mkdir -p .tmp
	$(PY) -m pytest -q -rs -m linux $(PYTEST_ARGS)

# Baseline, live watch and simulated tampering on a copy of the fixture under .tmp/demo.
demo:
	$(PY) scripts/demo.py

bench:
	@echo "M3: lab detection rate and false-alert rate during package updates"

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

ci: setup lint test
