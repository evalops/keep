package posture

import (
	"runtime"
	"strings"
)

const macOSDefaultRuleCount = 1

// MacOSCollector collects device posture on macOS systems
type MacOSCollector struct{}

// CollectPosture collects device posture information on macOS
func (c *MacOSCollector) CollectPosture() (*DevicePosture, error) {
	posture := &DevicePosture{
		OS: &OperatingSystem{
			Name: "macOS",
			Arch: runtime.GOARCH,
		},
		Firewall: &FirewallStatus{},
	}

	// Collect OS information
	if err := c.collectOSInfo(posture.OS); err != nil {
		return nil, err
	}

	// Collect firewall status
	if err := c.collectFirewallStatus(posture.Firewall); err != nil {
		// Non-fatal error, continue with default values
		*posture.Firewall = FirewallStatus{Service: UnknownService}
	}

	// Collect other security posture information
	posture.AntiVirus = c.checkAntiVirus()
	posture.SystemUpdate = c.checkSystemUpdated()
	posture.DiskEncrypted = c.checkDiskEncryption()
	posture.ScreenLock = c.checkScreenLock()

	// Calculate trust score
	posture.CalculateTrustScore()

	return posture, nil
}

// collectOSInfo gathers macOS information using system_profiler
func (c *MacOSCollector) collectOSInfo(os *OperatingSystem) error {
	// Get system version
	output, err := runCommand("system_profiler", "SPSoftwareDataType")
	if err != nil {
		return err
	}

	lines := strings.Split(output, newline)
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, macOSVersionKey) {
			parts := strings.SplitN(line, colonSeparator, keyValueParts)
			if len(parts) == keyValueParts {
				versionInfo := strings.TrimSpace(parts[1])
				// Parse "macOS Monterey 12.6.1 (21G217)"
				if strings.Contains(versionInfo, "(") {
					buildStart := strings.LastIndex(versionInfo, "(")
					buildEnd := strings.LastIndex(versionInfo, ")")
					if buildStart != notFoundIndex && buildEnd != notFoundIndex {
						os.Build = versionInfo[buildStart+indexIncrement : buildEnd]
						versionInfo = strings.TrimSpace(versionInfo[:buildStart])
					}
				}

				// Extract version number
				parts = strings.Fields(versionInfo)
				if len(parts) >= minPartsTriple {
					os.Name = strings.Join(parts[:keyValueParts], spaceSeparator)
					os.Version = parts[versionPartIndex]
				} else if len(parts) >= keyValueParts {
					os.Version = parts[len(parts)-indexIncrement]
				}
			}
		} else if strings.HasPrefix(line, macOSKernelKey) {
			parts := strings.SplitN(line, colonSeparator, keyValueParts)
			if len(parts) == keyValueParts {
				os.Kernel = strings.TrimSpace(parts[1])
			}
		}
	}

	// Check if OS version is supported (last 3 major versions typically)
	os.Supported = c.isOSSupported(os.Version)

	return nil
}

// collectFirewallStatus checks macOS firewall status
func (c *MacOSCollector) collectFirewallStatus(fw *FirewallStatus) error {
	_ = c
	fw.Service = macOSFirewallService

	// Check if firewall is enabled
	output, err := runCommand(defaultsCommand, readCommand, "/Library/Preferences/com.apple.alf", "globalstate")
	if err != nil {
		return err
	}

	state := strings.TrimSpace(output)
	fw.Enabled = state == macOSFirewallEnabled || state == macOSFirewallStealth

	// Get firewall rules (simplified - macOS firewall is less rule-based)
	if fw.Enabled {
		fw.Rules = macOSDefaultRuleCount
	}

	return nil
}

// checkAntiVirus checks for antivirus software on macOS
func (c *MacOSCollector) checkAntiVirus() bool {
	_ = c
	// Check for common macOS antivirus applications
	antivirusApps := []string{
		"/Applications/Bitdefender Virus Scanner.app",
		"/Applications/Sophos Home.app",
		"/Applications/Avast Security.app",
		"/Applications/AVG AntiVirus.app",
		"/Applications/Norton Security.app",
		"/Applications/Trend Micro Antivirus.app",
		"/Applications/ClamXav.app",
		"/Applications/Malwarebytes.app",
	}

	for _, app := range antivirusApps {
		if fileExists(app) {
			return true
		}
	}

	// Check XProtect (built-in)
	xprotectPaths := []string{
		"/System/Library/CoreServices/XProtect.bundle",
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
	}

	for _, path := range xprotectPaths {
		if fileExists(path) {
			return true
		}
	}

	return false
}

// checkSystemUpdated checks if system updates are available
func (c *MacOSCollector) checkSystemUpdated() bool {
	_ = c
	// Check for available updates
	output, err := runCommand("softwareupdate", "-l")
	if err != nil {
		return false
	}

	// If no updates, the output will contain "No new software available"
	lowerOutput := strings.ToLower(output)
	return strings.Contains(lowerOutput, macOSUpdateNoNew) ||
		strings.Contains(lowerOutput, macOSUpdateNoUpdates)
}

// checkDiskEncryption checks if FileVault is enabled
func (c *MacOSCollector) checkDiskEncryption() bool {
	_ = c
	output, err := runCommand("fdesetup", "status")
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(output), macOSFileVaultOn)
}

// checkScreenLock checks if screen lock/password is required
func (c *MacOSCollector) checkScreenLock() bool {
	_ = c
	// Check if password is required after screensaver
	output, err := runCommand(defaultsCommand, readCommand, "com.apple.screensaver", macOSScreenPassword)
	if err == nil && strings.Contains(output, macOSPasswordEnabled) {
		return true
	}

	// Check if password is required after sleep
	output, err = runCommand("pmset", "-g")
	if err == nil && strings.Contains(strings.ToLower(output), macOSSleepKeyword) {
		// If sleep is configured, assume password is required
		return true
	}

	// Check System Preferences security settings
	if _, err = runCommand(defaultsCommand, readCommand, "com.apple.screensaver", macOSScreenDelay); err == nil {
		return true
	}

	return false
}

// isOSSupported checks if the macOS version is supported
func (c *MacOSCollector) isOSSupported(version string) bool {
	_ = c
	if version == "" {
		return false
	}

	// Parse major version (e.g., "12.6.1" -> 12)
	parts := strings.Split(version, ".")
	if len(parts) == initialCapacity {
		return false
	}

	majorVersion := parseInt(parts[0])

	// Support last 3 major versions (as of 2024: macOS 12+)
	// This should be updated periodically
	return majorVersion >= MinMacOSVersion
}
