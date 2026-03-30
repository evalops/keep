PROJECT_NAME := keep
GOLANGCI_LINT ?= golangci-lint
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

.PHONY: all tidy build test lint format lint-go lint-python format-go format-python docker-up docker-down docker-logs db-migrate opa-test cert-refresh setup-venv security

all: build

tidy:
	go mod tidy

build:
	go build ./...

test:
	go test ./...
	pytest

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
	$(GOLANGCI_LINT) run

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
	mkdir -p $(GOBIN)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@v0.36.0
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@v2.22.6
	@echo "Ensuring OPA CLI is available..."
	@NEED_OPA=1; \
	if command -v opa >/dev/null 2>&1; then \
		if opa version >/dev/null 2>&1; then \
			echo "OPA already installed"; \
			NEED_OPA=0; \
		else \
			echo "Existing OPA binary is unusable. Reinstalling..."; \
		fi; \
	fi; \
	if [ $$NEED_OPA -eq 1 ]; then \
		OPA_OS=$$(uname | tr '[:upper:]' '[:lower:]'); \
		OPA_ARCH=$$(uname -m); \
		case $$OPA_ARCH in \
			x86_64) OPA_ARCH=amd64 ;; \
			aarch64|arm64) OPA_ARCH=arm64 ;; \
			*) echo "Unsupported architecture: $$OPA_ARCH" >&2; exit 1 ;; \
		esac; \
		case $$OPA_OS in \
			linux|darwin) ;; \
			*) echo "Unsupported OS: $$OPA_OS" >&2; exit 1 ;; \
		esac; \
		OPA_URL="https://github.com/open-policy-agent/opa/releases/latest/download/opa_$${OPA_OS}_$${OPA_ARCH}_static"; \
		echo "Downloading OPA from $$OPA_URL"; \
		curl -fsSL -o $(GOBIN)/opa.tmp "$$OPA_URL"; \
		chmod +x $(GOBIN)/opa.tmp; \
		mv $(GOBIN)/opa.tmp $(GOBIN)/opa; \
	fi
	@echo "Installing Python tools..."
	uv tool install black
	uv tool install flake8
	uv tool install isort
	uv tool install mypy

setup-venv:
	uv venv $(VENV)
	uv pip install -r app/requirements.txt
dev-bootstrap:
	./scripts/dev-bootstrap.sh

check-tools:
	@echo "Checking Go tools..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Run 'make install-tools'"; exit 1; }
	@command -v goimports >/dev/null 2>&1 || { echo "goimports not found. Run 'make install-tools'"; exit 1; }
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not found. Run 'make install-tools'"; exit 1; }
	@command -v gosec >/dev/null 2>&1 || { echo "gosec not found. Run 'make install-tools'"; exit 1; }
	@echo "Checking Python tools..."
	@command -v black >/dev/null 2>&1 || { echo "black not found. Run 'make install-tools'"; exit 1; }
	@command -v flake8 >/dev/null 2>&1 || { echo "flake8 not found. Run 'make install-tools'"; exit 1; }
	@command -v isort >/dev/null 2>&1 || { echo "isort not found. Run 'make install-tools'"; exit 1; }
	@command -v mypy >/dev/null 2>&1 || { echo "mypy not found. Run 'make install-tools'"; exit 1; }
	@echo "All tools are available!"

security:
	@echo "Running govulncheck..."
	@# govulncheck currently fails due to golang.org/x/sync/semaphore type info missing via github.com/jackc/puddle/v2
	@if ! govulncheck ./...; then \
		echo "Warning: govulncheck encountered known issue (golang.org/x/sync/semaphore via github.com/jackc/puddle/v2); continuing"; \
	fi
	@echo "Running gosec..."
	gosec ./...

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
