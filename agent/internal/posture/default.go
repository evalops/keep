package posture

import "runtime"

// DefaultCollector is a fallback collector for unsupported platforms
type DefaultCollector struct{}

// CollectPosture returns minimal posture information for unsupported platforms
func (c *DefaultCollector) CollectPosture() (*DevicePosture, error) {
	posture := &DevicePosture{
		OS: OperatingSystem{
			Name:      "Unknown",
			Version:   "Unknown",
			Build:     "Unknown",
			Arch:      runtime.GOARCH,
			Kernel:    "Unknown",
			Supported: false,
		},
		Firewall: FirewallStatus{
			Enabled: false,
			Rules:   0,
			Service: "unknown",
		},
		AntiVirus:     false,
		SystemUpdate:  false,
		DiskEncrypted: false,
		ScreenLock:    false,
	}

	// Calculate trust score (will be low due to unknown status)
	posture.CalculateTrustScore()

	return posture, nil
}
