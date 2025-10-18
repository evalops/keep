# Keep Attestor Agent

The Keep Attestor Agent is a refactored, robust service that collects real device posture information and maintains device identity through certificate management. This version replaces the simple CLI loop with proper service architecture.

## Features

### Real Device Posture Collection
- **Linux**: Checks `/etc/os-release`, UFW/iptables firewall, antivirus software, system updates, LUKS encryption, screen lock settings
- **macOS**: Uses `system_profiler`, checks built-in firewall, FileVault encryption, antivirus applications, system updates
- **Windows**: Queries WMI for OS info, Windows Defender Firewall, BitLocker encryption, antivirus status, Windows Update

### Service Architecture
- **Background Service**: Runs as proper daemon with systemd integration
- **Signal Handling**: Graceful shutdown on SIGTERM/SIGINT, configuration reload on SIGHUP
- **PID File Management**: Proper process management for service monitoring
- **Periodic Tasks**: Separate intervals for certificate renewal and posture updates
- **Logging**: Structured logging with configurable levels

### Trust Scoring
- Calculates trust score (0-100) based on security posture
- Status classification: `healthy` (80+), `compliant` (60+), `warning` (40+), `critical` (<40)

## Installation

### Development Build

```bash
# Build the binary
make build

# Show current device posture
make show-posture

# Run in development mode
make dev
```

### Production Installation (Linux with systemd)

```bash
# Install as systemd service
make install-service DEVICE_ID=laptop-001 \
  INVENTORY_URL=http://keep-inventory:8081 \
  AUTHZ_URL=http://keep-authz:8443

# Check service status
sudo systemctl status keep-attestor@laptop-001

# View logs
sudo journalctl -f -u keep-attestor@laptop-001
```

### Manual Installation

```bash
# Build and install binary
go build -o attestor-agent ./cmd/attestor-agent/
sudo cp attestor-agent /usr/local/bin/

# Run with custom configuration
attestor-agent \
  --device-id=laptop-001 \
  --inventory-url=http://inventory:8081 \
  --authz-url=http://authz:8443 \
  --refresh=15m \
  --posture-interval=5m \
  --daemon
```

## Configuration

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--device-id` | *required* | Unique device identifier |
| `--inventory-url` | `http://localhost:8081` | Inventory service URL |
| `--authz-url` | `http://localhost:8443` | Authorization service URL |
| `--key` | `./.keep/device.key` | Device private key path |
| `--cert` | `./.keep/device.crt` | Device certificate path |
| `--ca` | `./.keep/ca.pem` | Root CA certificate path |
| `--refresh` | `15m` | Certificate renewal interval |
| `--posture-interval` | `5m` | Posture update interval |
| `--log-level` | `info` | Log level (debug, info, warn, error) |
| `--pid-file` | | PID file path (daemon mode) |
| `--daemon` | `false` | Run as background daemon |
| `--show-posture` | `false` | Show posture and exit |

### Example Posture Output

```json
{
  "os": {
    "name": "Ubuntu 22.04.3 LTS",
    "version": "22.04",
    "build": "",
    "arch": "amd64",
    "kernel": "5.15.0-87-generic",
    "supported": true
  },
  "firewall": {
    "enabled": true,
    "rules": 12,
    "service": "ufw",
    "open_ports": []
  },
  "antivirus_enabled": false,
  "system_updated": true,
  "disk_encrypted": true,
  "screen_lock_enabled": true,
  "trust_score": 85,
  "status": "healthy"
}
```

## Service Management

### systemd Commands

```bash
# Service status
sudo systemctl status keep-attestor@DEVICE_ID

# Start/stop service
sudo systemctl start keep-attestor@DEVICE_ID
sudo systemctl stop keep-attestor@DEVICE_ID

# Enable/disable autostart
sudo systemctl enable keep-attestor@DEVICE_ID
sudo systemctl disable keep-attestor@DEVICE_ID

# View logs
sudo journalctl -u keep-attestor@DEVICE_ID
sudo journalctl -f -u keep-attestor@DEVICE_ID  # follow logs

# Reload service after config changes
sudo systemctl reload keep-attestor@DEVICE_ID
```

### Manual Service Control

```bash
# Send signals to running agent
kill -TERM $(cat /run/keep-agent/keep-attestor.pid)  # graceful shutdown
kill -HUP $(cat /run/keep-agent/keep-attestor.pid)   # reload config
```

## Development

### Project Structure

```
agent/
├── cmd/attestor-agent/          # Main application entry point
├── internal/
│   ├── posture/                 # Device posture collection
│   │   ├── posture.go          # Common types and interfaces
│   │   ├── linux.go            # Linux-specific collection
│   │   ├── macos.go            # macOS-specific collection
│   │   ├── windows.go          # Windows-specific collection
│   │   └── default.go          # Fallback for unknown OS
│   └── service/                 # Service management
│       └── service.go          # Service orchestration
├── scripts/                     # Installation scripts
│   ├── systemd/                # systemd service files
│   └── install-service.sh      # Service installer
├── Makefile                     # Build automation
└── README.md                    # This file
```

### Building and Testing

```bash
# Format code
make fmt

# Run tests
make test
make test-race

# Build for multiple platforms
make build-all

# Clean build artifacts
make clean
```

### Adding New Posture Collectors

To add support for a new operating system:

1. Create a new collector file (e.g., `freebsd.go`)
2. Implement the `Collector` interface:
   ```go
   type MyOSCollector struct{}
   
   func (c *MyOSCollector) CollectPosture() (*DevicePosture, error) {
       // Implementation
   }
   ```
3. Update `GetCollector()` in `posture.go` to return your collector for the appropriate OS

## Security Considerations

### File Permissions
- Private keys: `0600` (owner read/write only)
- Certificates: `0644` (world readable)
- Service runs as dedicated `keep-agent` user

### Network Security
- All API communication over HTTPS (in production)
- Certificate-based device authentication
- Regular certificate rotation

### System Access
- Service uses minimal privileges
- systemd security features enabled
- Read-only access to system information
- No modification of system settings

## Troubleshooting

### Common Issues

1. **Permission denied accessing system information**
   - Ensure agent runs with appropriate privileges
   - Check that `keep-agent` user can read required files

2. **Certificate renewal failures**
   - Verify authorization service connectivity
   - Check device registration status
   - Ensure valid CSR generation

3. **Posture collection errors**
   - Platform-specific command availability
   - Network access for update checks
   - File system permissions

### Debug Mode

```bash
# Run with debug logging
attestor-agent --device-id=debug-device --log-level=debug

# Show detailed posture information
attestor-agent --show-posture
```

### Log Locations

- systemd service: `journalctl -u keep-attestor@DEVICE_ID`
- Manual execution: stdout/stderr
- System logs: `/var/log/syslog` (on most Linux distributions)

## Migration from Legacy Agent

The refactored agent is backward compatible with the existing inventory and authorization services. To migrate:

1. Stop the old agent
2. Install the new agent with the same `device-id`
3. The new agent will automatically collect real posture data instead of using the static `--posture` flag

The new agent provides much richer posture information while maintaining the same API contracts.
