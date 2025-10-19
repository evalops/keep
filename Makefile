PROJECT_NAME := keep
VENV ?= .venv
VENV_BIN := $(VENV)/bin
PYTHON_BIN := python3
PIP_BIN := pip
FLAKE8_CMD := $(PYTHON_BIN) -m flake8
MYPY_CMD := $(PYTHON_BIN) -m mypy
BLACK_CMD := $(PYTHON_BIN) -m black
ISORT_CMD := $(PYTHON_BIN) -m isort
PYTEST_CMD := $(PYTHON_BIN) -m pytest
GOLANGCI_LINT ?= golangci-lint

ifneq ($(wildcard $(VENV_BIN)/python3),)
PYTHON_BIN := $(VENV_BIN)/python3
PIP_BIN := $(VENV_BIN)/pip
FLAKE8_BIN := $(VENV_BIN)/flake8
MYPY_BIN := $(VENV_BIN)/mypy
BLACK_BIN := $(VENV_BIN)/black
ISORT_BIN := $(VENV_BIN)/isort
PYTEST_CMD := $(PYTHON_BIN) -m pytest
endif

.PHONY: all tidy build test lint format lint-go lint-python format-go format-python docker-up docker-down docker-logs db-migrate opa-test cert-refresh setup-venv

all: build

tidy:
	go mod tidy

build:
	go build ./...

test:
	go test ./...
	$(PYTEST_CMD)

smoke:
	COMPOSE_FILE=docker-compose.yml ./scripts/smoke-tests.sh

# Formatting targets
format: format-go format-python

format-go:
	@echo "Formatting Go code..."
	go fmt ./...
	goimports -w -local github.com/EvalOps/keep .

format-python:
	@echo "Formatting Python code..."
	$(BLACK_CMD) app/
	$(ISORT_CMD) app/

# Linting targets  
lint: lint-go lint-python

lint-go:
	@echo "Linting Go code..."
	go mod download
	$(GOLANGCI_LINT) run

lint-python:
	@echo "Linting Python code..."
	$(FLAKE8_CMD) app/
	$(MYPY_CMD) app/ --ignore-missing-imports

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

db-migrate:
	go run ./cmd/migrate -direction=up

db-migrate-down:
	go run ./cmd/migrate -direction=down

db-migrate-status:
	go run ./cmd/migrate -version

opa-test:
	opa test ./policies

cert-refresh:
	go run ./cmd/authz cert-refresh

# Tool installation and checks
install-tools:
	@echo "Installing Go tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "Installing Python tools..."
	$(PIP_BIN) install black flake8 isort mypy

setup-venv:
	python3 -m venv $(VENV)
	$(VENV_BIN)/python3 -m pip install --upgrade pip
	$(VENV_BIN)/pip install -r app/requirements.txt
dev-bootstrap:
	./scripts/dev-bootstrap.sh

check-tools:
	@echo "Checking Go tools..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Run 'make install-tools'"; exit 1; }
	@command -v goimports >/dev/null 2>&1 || { echo "goimports not found. Run 'make install-tools'"; exit 1; }
	@echo "Checking Python tools..."
	@$(BLACK_CMD) --version >/dev/null 2>&1 || { echo "black not available. Run 'make install-tools'"; exit 1; }
	@$(FLAKE8_CMD) --version >/dev/null 2>&1 || { echo "flake8 not available. Run 'make install-tools'"; exit 1; }
	@$(ISORT_CMD) --version >/dev/null 2>&1 || { echo "isort not available. Run 'make install-tools'"; exit 1; }
	@$(MYPY_CMD) --version >/dev/null 2>&1 || { echo "mypy not available. Run 'make install-tools'"; exit 1; }
	@echo "All tools are available!"

# CI/CD targets
ci-lint: check-tools lint
ci-test: check-tools test
ci-format-check: check-tools
	@echo "Checking Go formatting..."
	@if [ "$$(gofmt -l . | wc -l)" -ne 0 ]; then echo "Go files need formatting. Run 'make format-go'"; exit 1; fi
	@echo "Checking Python formatting..."
	@black --check app/ || { echo "Python files need formatting. Run 'make format-python'"; exit 1; }
	@isort --check-only app/ || { echo "Python imports need sorting. Run 'make format-python'"; exit 1; }

# Help target
help:
	@echo "Available targets:"
	@echo "  build            - Build all Go packages"
	@echo "  test             - Run all Go tests"
	@echo "  lint             - Run all linters (Go + Python)"
	@echo "  format           - Format all code (Go + Python)"
	@echo "  lint-go          - Run Go linters only"
	@echo "  lint-python      - Run Python linters only"
	@echo "  format-go        - Format Go code only"
	@echo "  format-python    - Format Python code only"
	@echo "  install-tools    - Install linting and formatting tools"
	@echo "  check-tools      - Verify required tools are installed"
	@echo "  ci-lint          - CI-friendly linting"
	@echo "  ci-test          - CI-friendly testing"
	@echo "  ci-format-check  - CI-friendly format checking"
	@echo "  docker-up        - Start Docker Compose services"
	@echo "  docker-down      - Stop Docker Compose services"
	@echo "  help             - Show this help"
