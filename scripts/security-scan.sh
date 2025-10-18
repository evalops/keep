#!/usr/bin/env bash
set -euo pipefail

echo "Running gosec"
gosec -severity medium ./...

echo "Running govulncheck"
govulncheck ./...

echo "Running Trivy filesystem scan"
trivy fs --no-progress --exit-code 1 --severity HIGH,CRITICAL .
