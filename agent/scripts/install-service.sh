#!/bin/bash

# Install script for Keep Attestor Agent
set -e

DEVICE_ID="$1"
INVENTORY_URL="${2:-http://localhost:8081}"
AUTHZ_URL="${3:-http://localhost:8443}"

if [ -z "$DEVICE_ID" ]; then
    echo "Usage: $0 <device-id> [inventory-url] [authz-url]"
    echo "Example: $0 laptop-001 http://keep-inventory:8081 http://keep-authz:8443"
    exit 1
fi

echo "Installing Keep Attestor Agent..."

# Create user and group
if ! id keep-agent >/dev/null 2>&1; then
    echo "Creating keep-agent user..."
    sudo useradd --system --shell /bin/false --home /var/lib/keep-agent keep-agent
fi

# Create directories
echo "Creating directories..."
sudo mkdir -p /var/lib/keep-agent
sudo mkdir -p /run/keep-agent
sudo mkdir -p /usr/local/bin
sudo mkdir -p /etc/systemd/system

# Set ownership and permissions
sudo chown keep-agent:keep-agent /var/lib/keep-agent
sudo chmod 750 /var/lib/keep-agent
sudo chown keep-agent:keep-agent /run/keep-agent
sudo chmod 755 /run/keep-agent

# Build and install the binary
echo "Building attestor-agent..."
cd "$(dirname "$0")/.."
go build -o attestor-agent ./cmd/attestor-agent/
sudo cp attestor-agent /usr/local/bin/
sudo chmod 755 /usr/local/bin/attestor-agent
sudo chown root:root /usr/local/bin/attestor-agent

# Create systemd service file
echo "Installing systemd service..."
sudo cp scripts/systemd/keep-attestor.service /etc/systemd/system/keep-attestor@.service

# Update service file with provided URLs
sudo sed -i "s|--inventory-url=http://localhost:8081|--inventory-url=$INVENTORY_URL|g" /etc/systemd/system/keep-attestor@.service
sudo sed -i "s|--authz-url=http://localhost:8443|--authz-url=$AUTHZ_URL|g" /etc/systemd/system/keep-attestor@.service

# Reload systemd
sudo systemctl daemon-reload

# Enable and start the service
echo "Enabling and starting the service..."
sudo systemctl enable keep-attestor@"$DEVICE_ID".service
sudo systemctl start keep-attestor@"$DEVICE_ID".service

echo ""
echo "Keep Attestor Agent installed successfully!"
echo "Device ID: $DEVICE_ID"
echo "Inventory URL: $INVENTORY_URL"
echo "Authorization URL: $AUTHZ_URL"
echo ""
echo "Service commands:"
echo "  Status:  sudo systemctl status keep-attestor@$DEVICE_ID"
echo "  Stop:    sudo systemctl stop keep-attestor@$DEVICE_ID"
echo "  Start:   sudo systemctl start keep-attestor@$DEVICE_ID"
echo "  Logs:    sudo journalctl -f -u keep-attestor@$DEVICE_ID"
echo "  Posture: /usr/local/bin/attestor-agent --show-posture"
