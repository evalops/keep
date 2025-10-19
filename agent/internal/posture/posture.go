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

// TrustStatus represents the overall posture state and is stored as a compact enumeration.
type TrustStatus uint8

const (
	TrustStatusUnknown TrustStatus = iota
	TrustStatusHealthy
	TrustStatusCompliant
	TrustStatusWarning
	TrustStatusCritical
)

func (ts TrustStatus) String() string {
	switch ts {
	case TrustStatusHealthy:
		return StatusHealthy
	case TrustStatusCompliant:
		return StatusCompliant
	case TrustStatusWarning:
		return StatusWarning
	case TrustStatusCritical:
		return StatusCritical
	default:
		return StatusCritical
	}
}

// MarshalJSON encodes the trust status as its string representation.
func (ts TrustStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(ts.String())
}

// UnmarshalJSON decodes a trust status from its textual representation.
func (ts *TrustStatus) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch strings.ToLower(value) {
	case StatusHealthy:
		*ts = TrustStatusHealthy
	case StatusCompliant:
		*ts = TrustStatusCompliant
	case StatusWarning:
		*ts = TrustStatusWarning
	case StatusCritical:
		*ts = TrustStatusCritical
	default:
		*ts = TrustStatusUnknown
	}
	return nil
}

// DevicePosture represents the security posture of a device
type DevicePosture struct {
	OS         *OperatingSystem `json:"os"`
	Firewall   *FirewallStatus  `json:"firewall"`
	TrustScore int              `json:"trust_score"`
	Status     TrustStatus      `json:"status"`
	SecurityFeatureSet
}

// SecurityFeatureSet groups boolean security attributes and is embedded for JSON compatibility.
type SecurityFeatureSet struct {
	AntiVirus     bool `json:"antivirus_enabled"`
	SystemUpdate  bool `json:"system_updated"`
	DiskEncrypted bool `json:"disk_encrypted"`
	ScreenLock    bool `json:"screen_lock_enabled"`
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
	Service string   `json:"service"`
	Ports   []string `json:"open_ports"`
	Rules   int      `json:"rules"`
	Enabled bool     `json:"enabled"`
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

	if p.OS != nil && p.OS.Supported {
		score += TrustBonusOS
	}

	if p.Firewall != nil && p.Firewall.Enabled {
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
		p.Status = TrustStatusHealthy
	case score >= TrustThresholdCompliant:
		p.Status = TrustStatusCompliant
	case score >= TrustThresholdWarning:
		p.Status = TrustStatusWarning
	default:
		p.Status = TrustStatusCritical
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

		parts := strings.SplitN(line, "=", keyValueParts)
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
