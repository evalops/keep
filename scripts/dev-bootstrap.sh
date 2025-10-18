#!/usr/bin/env bash
set -euo pipefail

echo "Installing Go tools"
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

echo "Setting up Python environment"
if [ -f "app/requirements.txt" ]; then
  python3 -m pip install --upgrade pip
  python3 -m pip install -r app/requirements.txt
fi

echo "Tidying Go modules"
go mod tidy

echo "Running lint and tests"
make lint
make test
