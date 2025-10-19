package posture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestGetCollector tests the collector factory function
func TestGetCollector(t *testing.T) {
	collector := GetCollector()

	if collector == nil {
		t.Fatal("Expected collector, got nil")
	}

	// The type will depend on the OS the test is running on
	switch collector.(type) {
	case *LinuxCollector, *MacOSCollector, *WindowsCollector, *DefaultCollector:
		// Valid collector types
	default:
		t.Errorf("Unexpected collector type: %T", collector)
	}
}

// TestDevicePosture_CalculateTrustScore tests trust score calculation
func TestDevicePosture_CalculateTrustScore(t *testing.T) {
	testCases := []struct {
		name           string
		posture        DevicePosture
		expectedScore  int
		expectedStatus string
	}{
		{
			name: "perfect security posture",
			posture: DevicePosture{
				OS:            OperatingSystem{Supported: true},
				Firewall:      FirewallStatus{Enabled: true},
				AntiVirus:     true,
				SystemUpdate:  true,
				DiskEncrypted: true,
				ScreenLock:    true,
			},
			expectedScore:  100,
			expectedStatus: StatusHealthy,
		},
		{
			name: "good security posture",
			posture: DevicePosture{
				OS:            OperatingSystem{Supported: true},
				Firewall:      FirewallStatus{Enabled: true},
				AntiVirus:     false,
				SystemUpdate:  true,
				DiskEncrypted: true,
				ScreenLock:    true,
			},
			expectedScore:  85,
			expectedStatus: StatusHealthy,
		},
		{
			name: "compliant security posture",
			posture: DevicePosture{
				OS:            OperatingSystem{Supported: true},
				Firewall:      FirewallStatus{Enabled: true},
				AntiVirus:     false,
				SystemUpdate:  false,
				DiskEncrypted: true,
				ScreenLock:    false,
			},
			expectedScore:  60,
			expectedStatus: StatusCompliant,
		},
		{
			name: "warning security posture",
			posture: DevicePosture{
				OS:            OperatingSystem{Supported: false},
				Firewall:      FirewallStatus{Enabled: true},
				AntiVirus:     false,
				SystemUpdate:  false,
				DiskEncrypted: false,
				ScreenLock:    true,
			},
			expectedScore:  30,
			expectedStatus: StatusCritical,
		},
		{
			name: "critical security posture",
			posture: DevicePosture{
				OS:            OperatingSystem{Supported: false},
				Firewall:      FirewallStatus{Enabled: false},
				AntiVirus:     false,
				SystemUpdate:  false,
				DiskEncrypted: false,
				ScreenLock:    false,
			},
			expectedScore:  0,
			expectedStatus: StatusCritical,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			posture := tc.posture
			posture.CalculateTrustScore()

			if posture.TrustScore != tc.expectedScore {
				t.Errorf("Expected trust score %d, got %d", tc.expectedScore, posture.TrustScore)
			}

			if posture.Status != tc.expectedStatus {
				t.Errorf("Expected status %s, got %s", tc.expectedStatus, posture.Status)
			}
		})
	}
}

// TestDevicePosture_ToJSON tests JSON serialization
func TestDevicePosture_ToJSON(t *testing.T) {
	posture := &DevicePosture{
		OS: OperatingSystem{
			Name:      "Ubuntu 22.04",
			Version:   "22.04",
			Arch:      "amd64",
			Supported: true,
		},
		Firewall: FirewallStatus{
			Enabled: true,
			Rules:   10,
			Service: "ufw",
		},
		AntiVirus:     false,
		SystemUpdate:  true,
		DiskEncrypted: true,
		ScreenLock:    true,
		TrustScore:    85,
		Status:        StatusHealthy,
	}

	jsonStr, err := posture.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if jsonStr == "" {
		t.Error("Expected JSON string, got empty string")
	}

	// Verify it's valid JSON by parsing it back
	var parsed DevicePosture
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Errorf("Invalid JSON produced: %v", err)
	}

	// Verify some key fields
	if parsed.OS.Name != posture.OS.Name {
		t.Errorf("Expected OS name %s, got %s", posture.OS.Name, parsed.OS.Name)
	}

	if parsed.TrustScore != posture.TrustScore {
		t.Errorf("Expected trust score %d, got %d", posture.TrustScore, parsed.TrustScore)
	}

	if parsed.Status != posture.Status {
		t.Errorf("Expected status %s, got %s", posture.Status, parsed.Status)
	}
}

// TestParseKeyValue tests key-value parsing utility
func TestParseKeyValue(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name: "simple key-value pairs",
			input: `NAME=Ubuntu
VERSION="22.04 LTS"
ID=ubuntu`,
			expected: map[string]string{
				"NAME":    "Ubuntu",
				"VERSION": "22.04 LTS",
				"ID":      "ubuntu",
			},
		},
		{
			name: "with comments and empty lines",
			input: `# This is a comment
NAME=Test

VERSION=1.0
# Another comment
ID=test`,
			expected: map[string]string{
				"NAME":    "Test",
				"VERSION": "1.0",
				"ID":      "test",
			},
		},
		{
			name: "with quoted values",
			input: `NAME="Ubuntu Server"
VERSION="20.04 LTS"
ID=ubuntu`,
			expected: map[string]string{
				"NAME":    "Ubuntu Server",
				"VERSION": "20.04 LTS",
				"ID":      "ubuntu",
			},
		},
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name: "malformed lines",
			input: `NAME=Ubuntu
INVALID_LINE_WITHOUT_EQUALS
VERSION=22.04`,
			expected: map[string]string{
				"NAME":    "Ubuntu",
				"VERSION": "22.04",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseKeyValue(tc.input)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestParseInt tests integer parsing utility
func TestParseInt(t *testing.T) {
	testCases := []struct {
		input    string
		expected int
	}{
		{"123", 123},
		{"0", 0},
		{"-456", -456},
		{"invalid", 0},
		{"", 0},
		{"12.34", 0}, // Should fail for non-integer
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := parseInt(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %d, got %d", tc.expected, result)
			}
		})
	}
}

// TestFileExists tests file existence utility
func TestFileExists(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("returns true for existing file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "exists.txt")
		if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		if !fileExists(testFile) {
			t.Error("Expected true for existing file")
		}
	})

	t.Run("returns false for non-existent file", func(t *testing.T) {
		nonExistentFile := filepath.Join(tmpDir, "does-not-exist.txt")

		if fileExists(nonExistentFile) {
			t.Error("Expected false for non-existent file")
		}
	})

	t.Run("returns true for directory", func(t *testing.T) {
		// fileExists checks if a path exists, including directories
		if !fileExists(tmpDir) {
			t.Error("Expected true for directory path")
		}
	})
}
