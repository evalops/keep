#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=${1:-staging}

echo "Building images for environment: ${ENVIRONMENT}"

docker build -t keep/authz:${ENVIRONMENT} -f services/authz/Dockerfile .
docker build -t keep/inventory:${ENVIRONMENT} -f services/inventory/Dockerfile .
docker build -t keep/app:${ENVIRONMENT} -f app/Dockerfile .

echo "Applying Kubernetes manifests (dry-run)"
kubectl apply --dry-run=client -k deploy/kubernetes
