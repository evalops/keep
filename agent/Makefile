.PHONY: build test clean install-service uninstall-service show-posture

# Build the attestor agent
build:
	go build -o attestor-agent ./cmd/attestor-agent/

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o attestor-agent-linux-amd64 ./cmd/attestor-agent/
	GOOS=darwin GOARCH=amd64 go build -o attestor-agent-darwin-amd64 ./cmd/attestor-agent/
	GOOS=darwin GOARCH=arm64 go build -o attestor-agent-darwin-arm64 ./cmd/attestor-agent/
	GOOS=windows GOARCH=amd64 go build -o attestor-agent-windows-amd64.exe ./cmd/attestor-agent/

# Run tests
test:
	go test -v ./internal/...

# Test with race detection
test-race:
	go test -race -v ./internal/...

# Clean build artifacts
clean:
	rm -f attestor-agent
	rm -f attestor-agent-*

# Show current device posture (for development/testing)
show-posture:
	go run ./cmd/attestor-agent/ --show-posture

# Run the agent in development mode
dev:
	go run ./cmd/attestor-agent/ --device-id=dev-$(shell hostname) --refresh=1m --posture-interval=30s

# Install as systemd service (Linux only)
install-service:
	@echo "Usage: make install-service DEVICE_ID=<device-id> [INVENTORY_URL=<url>] [AUTHZ_URL=<url>]"
	@echo "Example: make install-service DEVICE_ID=laptop-001"
	@if [ -z "$(DEVICE_ID)" ]; then \
		echo "Error: DEVICE_ID is required"; \
		exit 1; \
	fi
	./scripts/install-service.sh $(DEVICE_ID) $(INVENTORY_URL) $(AUTHZ_URL)

# Uninstall systemd service
uninstall-service:
	@echo "Usage: make uninstall-service DEVICE_ID=<device-id>"
	@if [ -z "$(DEVICE_ID)" ]; then \
		echo "Error: DEVICE_ID is required"; \
		exit 1; \
	fi
	sudo systemctl stop keep-attestor@$(DEVICE_ID) || true
	sudo systemctl disable keep-attestor@$(DEVICE_ID) || true
	sudo rm -f /etc/systemd/system/keep-attestor@.service
	sudo systemctl daemon-reload
	@echo "Service uninstalled. Binary and data remain in /usr/local/bin and /var/lib/keep-agent"

# Format code
fmt:
	go fmt ./...

# Run linting
lint:
	golangci-lint run

# Generate mocks for testing
generate:
	go generate ./...

# Help
help:
	@echo "Available targets:"
	@echo "  build            - Build the attestor agent binary"
	@echo "  build-all        - Build for multiple platforms"
	@echo "  test             - Run tests"
	@echo "  test-race        - Run tests with race detection"
	@echo "  clean            - Clean build artifacts"
	@echo "  show-posture     - Show current device posture"
	@echo "  dev              - Run agent in development mode"
	@echo "  install-service  - Install as systemd service (requires DEVICE_ID)"
	@echo "  uninstall-service - Uninstall systemd service (requires DEVICE_ID)"
	@echo "  fmt              - Format code"
	@echo "  lint             - Run linting"
	@echo "  generate         - Generate mocks"
	@echo "  help             - Show this help"
