# Helper commands
.PHONY: setup lint test docs-serve docs-build pester

setup:
	python -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

lint:
	. .venv/bin/activate && pip install flake8 && flake8 src --max-line-length=120 --extend-ignore=E203,W503 || true

test:
	. .venv/bin/activate && pip install pytest && pytest -q

pester:
	pwsh -NoLogo -NoProfile -Command "Invoke-Pester -Path tests/pester -CI"

docs-serve:
	. .venv/bin/activate && pip install mkdocs mkdocs-material && mkdocs serve -a 127.0.0.1:8002

docs-build:
	. .venv/bin/activate && pip install mkdocs mkdocs-material && mkdocs build
