PROJECT_NAME := keep

.PHONY: all tidy build test lint format lint-go lint-python format-go format-python docker-up docker-down docker-logs db-migrate opa-test cert-refresh

all: build

tidy:
	go mod tidy

build:
	go build ./...

test:
	go test ./...
	python3 -m pytest

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
	black app/
	isort app/

# Linting targets  
lint: lint-go lint-python

lint-go:
	@echo "Linting Go code..."
	go mod download
	golangci-lint run

lint-python:
	@echo "Linting Python code..."
	flake8 app/
	mypy app/ --ignore-missing-imports

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
	pip install black flake8 isort mypy
dev-bootstrap:
	./scripts/dev-bootstrap.sh

check-tools:
	@echo "Checking Go tools..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Run 'make install-tools'"; exit 1; }
	@command -v goimports >/dev/null 2>&1 || { echo "goimports not found. Run 'make install-tools'"; exit 1; }
	@echo "Checking Python tools..."
	@command -v black >/dev/null 2>&1 || { echo "black not found. Run 'make install-tools'"; exit 1; }
	@command -v flake8 >/dev/null 2>&1 || { echo "flake8 not found. Run 'make install-tools'"; exit 1; }
	@command -v isort >/dev/null 2>&1 || { echo "isort not found. Run 'make install-tools'"; exit 1; }
	@command -v mypy >/dev/null 2>&1 || { echo "mypy not found. Run 'make install-tools'"; exit 1; }
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
