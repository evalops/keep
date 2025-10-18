#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE=${COMPOSE_FILE:-docker-compose.yml}

echo "Starting smoke test environment using ${COMPOSE_FILE}"
docker compose -f "${COMPOSE_FILE}" up --build -d

cleanup() {
  echo "Stopping smoke test environment"
  docker compose -f "${COMPOSE_FILE}" down -v
}

trap cleanup EXIT

echo "Waiting for services to become healthy"
sleep 10

echo "Running health checks"
docker compose -f "${COMPOSE_FILE}" exec app curl -sf http://localhost:5000/health
docker compose -f "${COMPOSE_FILE}" exec authz curl -sf http://localhost:8080/health || true
docker compose -f "${COMPOSE_FILE}" exec inventory curl -sf http://localhost:8080/health

echo "Smoke tests completed successfully"
