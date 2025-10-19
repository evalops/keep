package posture

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// DevicePosture represents the security posture of a device
type DevicePosture struct {
	OS            OperatingSystem `json:"os"`
	Firewall      FirewallStatus  `json:"firewall"`
	TrustScore    int             `json:"trust_score"`
	Status        string          `json:"status"`
	AntiVirus     bool            `json:"antivirus_enabled"`
	SystemUpdate  bool            `json:"system_updated"`
	DiskEncrypted bool            `json:"disk_encrypted"`
	ScreenLock    bool            `json:"screen_lock_enabled"`
}

// OperatingSystem contains OS information
type OperatingSystem struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Build     string `json:"build"`
	Arch      string `json:"arch"`
	Kernel    string `json:"kernel"`
	Supported bool   `json:"supported"`
}

// FirewallStatus contains firewall information
type FirewallStatus struct {
	Enabled bool     `json:"enabled"`
	Rules   int      `json:"rules"`
	Service string   `json:"service"`
	Ports   []string `json:"open_ports"`
}

// Collector defines the interface for collecting device posture
type Collector interface {
	CollectPosture() (*DevicePosture, error)
}

// GetCollector returns the appropriate posture collector for the current OS
func GetCollector() Collector {
	switch runtime.GOOS {
	case "linux":
		return &LinuxCollector{}
	case "darwin":
		return &MacOSCollector{}
	case "windows":
		return &WindowsCollector{}
	default:
		return &DefaultCollector{}
	}
}

// ToJSON converts the posture to JSON string
func (p *DevicePosture) ToJSON() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// CalculateTrustScore calculates an overall trust score based on posture
func (p *DevicePosture) CalculateTrustScore() {
	score := DefaultRules

	if p.OS.Supported {
		score += TrustBonusOS
	}

	if p.Firewall.Enabled {
		score += TrustBonusFirewall
	}

	if p.AntiVirus {
		score += TrustBonusAntiVirus
	}

	if p.SystemUpdate {
		score += TrustBonusUpdate
	}

	if p.DiskEncrypted {
		score += TrustBonusEncrypted
	}

	if p.ScreenLock {
		score += TrustBonusScreenLock
	}

	p.TrustScore = score

	// Set status based on score
	switch {
	case score >= TrustThresholdHealthy:
		p.Status = StatusHealthy
	case score >= TrustThresholdCompliant:
		p.Status = StatusCompliant
	case score >= TrustThresholdWarning:
		p.Status = StatusWarning
	default:
		p.Status = StatusCritical
	}
}

// execCommand is a wrapper around exec.Command for testing
var execCommand = exec.Command

// readFile is a wrapper around os.ReadFile for testing
var readFile = os.ReadFile

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// runCommand executes a command and returns its output
func runCommand(name string, args ...string) (string, error) {
	cmd := execCommand(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// parseKeyValue parses key=value pairs from text
func parseKeyValue(text string) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(text))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == emptyString || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == keyValueParts {
			key := strings.TrimSpace(parts[0])
			value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			result[key] = value
		}
	}

	return result
}

// parseInt safely converts a string to int
func parseInt(s string) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return DefaultRules
}
