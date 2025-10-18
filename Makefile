PROJECT_NAME := keep

.PHONY: all tidy build test lint docker-up docker-down docker-logs db-migrate opa-test cert-refresh

all: build

tidy:
	go mod tidy

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

db-migrate:
	go run ./cmd/attestor migrate

opa-test:
	opa test ./policies

cert-refresh:
	go run ./cmd/authz cert-refresh
