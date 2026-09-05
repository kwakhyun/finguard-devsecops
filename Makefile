.PHONY: help test quality integration-release scan demo-pass demo-fail verify onprem-validate onprem-up clean

PYTHON ?= .venv/bin/python
BUILD_DIR ?= build
QUALITY_REPORT_DIR ?= $(BUILD_DIR)/quality-reports

help:
	@echo "test       Run the unit and integration test suite"
	@echo "quality    Run formatter, lint, typing, tests, and coverage checks"
	@echo "integration-release  Exercise real kind deployment, Cosign, failure, and interruption"
	@echo "scan       Run local lint, SAST, and dependency hygiene scans"
	@echo "demo-pass  Evaluate the passing policy scenario"
	@echo "demo-fail  Evaluate the intentionally blocked scenario"
	@echo "verify     Verify the passing demo evidence bundle"
	@echo "onprem-up  Validate image digests and start the local on-prem stack"

test:
	$(PYTHON) -m pytest -q

integration-release:
	$(PYTHON) scripts/integration_release.py --output $(BUILD_DIR)/integration-release

quality:
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy finguard sample_service
	mkdir -p "$(QUALITY_REPORT_DIR)"
	$(PYTHON) -m ruff check . --exit-zero --output-format=json --output-file="$(QUALITY_REPORT_DIR)/ruff.json"
	$(PYTHON) -m pytest -q --cov=finguard --cov-fail-under=85 \
		--junitxml="$(QUALITY_REPORT_DIR)/junit.xml" \
		--cov-report=term-missing --cov-report=xml:"$(QUALITY_REPORT_DIR)/coverage.xml"

scan:
	$(PYTHON) -m finguard scan source --workspace . --output $(BUILD_DIR)/reports/native
	$(PYTHON) -m finguard scan lint --workspace . --output $(BUILD_DIR)/reports/native
	$(PYTHON) -m finguard scan dependencies --workspace . --output $(BUILD_DIR)/reports/native

demo-pass:
	$(PYTHON) -m finguard demo --scenario pass --output $(BUILD_DIR)/demo-evidence --force

demo-fail:
	@$(PYTHON) -m finguard demo --scenario fail --output $(BUILD_DIR)/demo-evidence --force; \
	code=$$?; test $$code -eq 2

verify:
	$(PYTHON) -m finguard verify --evidence $(BUILD_DIR)/demo-evidence/pass --allow-unsigned

onprem-validate:
	$(PYTHON) scripts/validate_onprem_images.py

onprem-up: onprem-validate
	docker compose -f infra/docker-compose.onprem.yml up -d

clean:
	$(PYTHON) scripts/clean_build.py
