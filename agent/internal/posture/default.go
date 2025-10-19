package posture

import "runtime"

// DefaultCollector is a fallback collector for unsupported platforms
type DefaultCollector struct{}

// CollectPosture returns minimal posture information for unsupported platforms
func (c *DefaultCollector) CollectPosture() (*DevicePosture, error) {
	_ = c
	posture := &DevicePosture{
		OS: &OperatingSystem{
			Name:      UnknownValue,
			Version:   UnknownValue,
			Build:     UnknownValue,
			Arch:      runtime.GOARCH,
			Kernel:    UnknownValue,
			Supported: false,
		},
		Firewall: &FirewallStatus{
			Service: UnknownService,
			Ports:   nil,
			Rules:   DefaultRules,
			Enabled: false,
		},
		SecurityFeatureSet: SecurityFeatureSet{
			AntiVirus:     false,
			SystemUpdate:  false,
			DiskEncrypted: false,
			ScreenLock:    false,
		},
	}

	// Calculate trust score (will be low due to unknown status)
	posture.CalculateTrustScore()

	return posture, nil
}
