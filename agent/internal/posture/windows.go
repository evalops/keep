package posture

import (
	"runtime"
	"strings"
)

const (
	newlineSeparator     = "\n"
	ruleNamePrefix       = "Rule Name:"
	displayNamePrefix    = "displayName="
	displayNamePrefixLen = len(displayNamePrefix)
	powershellCmd        = "powershell"
	powershellFlag       = "-Command"
)

// WindowsCollector collects device posture on Windows systems
type WindowsCollector struct{}

// CollectPosture collects device posture information on Windows
func (c *WindowsCollector) CollectPosture() (*DevicePosture, error) {
	posture := &DevicePosture{
		OS: OperatingSystem{
			Name: "Windows",
			Arch: runtime.GOARCH,
		},
	}

	// Collect OS information
	if err := c.collectOSInfo(&posture.OS); err != nil {
		return nil, err
	}

	// Collect firewall status
	if err := c.collectFirewallStatus(&posture.Firewall); err != nil {
		// Non-fatal error, continue with default values
		posture.Firewall = FirewallStatus{Enabled: false, Service: "unknown"}
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

// collectOSInfo gathers Windows OS information
func (c *WindowsCollector) collectOSInfo(os *OperatingSystem) error {
	// Get Windows version using wmic
	output, err := runCommand("wmic", "os", "get", "Caption,Version,BuildNumber", "/format:list")
	if err != nil {
		return err
	}

	lines := strings.Split(output, newlineSeparator)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "Caption=") {
			os.Name = strings.TrimPrefix(line, "Caption=")
		} else if strings.HasPrefix(line, "Version=") {
			os.Version = strings.TrimPrefix(line, "Version=")
		} else if strings.HasPrefix(line, "BuildNumber=") {
			os.Build = strings.TrimPrefix(line, "BuildNumber=")
		}
	}

	// Get kernel version (same as version on Windows)
	os.Kernel = os.Version

	// Check if OS version is supported
	os.Supported = c.isOSSupported(os.Version)

	return nil
}

// collectFirewallStatus checks Windows Defender Firewall status
func (c *WindowsCollector) collectFirewallStatus(fw *FirewallStatus) error {
	fw.Service = "Windows Defender Firewall"

	// Check firewall state using netsh
	output, err := runCommand("netsh", "advfirewall", "show", "allprofiles", "state")
	if err != nil {
		return err
	}

	// Check if any profile is enabled
	fw.Enabled = strings.Contains(strings.ToLower(output), "state                                 on")

	// Count rules (simplified)
	if fw.Enabled {
		ruleOutput, err := runCommand("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
		if err == nil {
			lines := strings.Split(ruleOutput, newlineSeparator)
			ruleCount := 0
			for _, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), ruleNamePrefix) {
					ruleCount++
				}
			}
			fw.Rules = ruleCount
		}
	}

	return nil
}

// checkAntiVirus checks Windows Defender and other antivirus software
func (c *WindowsCollector) checkAntiVirus() bool {
	// Check Windows Defender status
	output, err := runCommand(powershellCmd, powershellFlag, "Get-MpComputerStatus | Select-Object AntivirusEnabled")
	if err == nil && strings.Contains(strings.ToLower(output), "true") {
		return true
	}

	// Check for other antivirus software using WMI
	output, err = runCommand("wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntiVirusProduct", "get", "displayName", "/format:list")
	if err == nil {
		lines := strings.Split(output, newlineSeparator)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, displayNamePrefix) && len(line) > displayNamePrefixLen {
				return true // Found antivirus software
			}
		}
	}

	return false
}

// checkSystemUpdated checks Windows Update status
func (c *WindowsCollector) checkSystemUpdated() bool {
	// Check for pending updates using PowerShell
	output, err := runCommand(powershellCmd, powershellFlag,
		"Get-WUList -MicrosoftUpdate | Measure-Object | Select-Object -ExpandProperty Count")
	if err == nil {
		count := parseInt(strings.TrimSpace(output))
		return count == 0 // No pending updates
	}

	// Fallback: check Windows Update service
	output, err = runCommand("sc", "query", "wuauserv")
	if err == nil {
		return strings.Contains(strings.ToUpper(output), "RUNNING")
	}

	return false
}

// checkDiskEncryption checks BitLocker status
func (c *WindowsCollector) checkDiskEncryption() bool {
	// Check BitLocker status
	output, err := runCommand("manage-bde", "-status")
	if err != nil {
		return false
	}

	return strings.Contains(strings.ToLower(output), "protection on") ||
		strings.Contains(strings.ToLower(output), "fully encrypted")
}

// checkScreenLock checks screen lock/password policy
func (c *WindowsCollector) checkScreenLock() bool {
	// Check screen saver settings
	output, err := runCommand("reg", "query",
		"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
		"/v", "ScreenSaveActive")
	if err == nil && strings.Contains(output, "0x1") {
		return true
	}

	// Check password policy
	output, err = runCommand("net", "accounts")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), "minimum password length") {
				if strings.Contains(line, "0") {
					return false // No password required
				}
				return true
			}
		}
	}

	// Check lock screen settings
	output, err = runCommand(powershellCmd, powershellFlag,
		"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name DisableCAD -ErrorAction SilentlyContinue")
	if err == nil && !strings.Contains(output, "1") {
		return true // Ctrl+Alt+Del required (indicates password policy)
	}

	return false
}

// isOSSupported checks if the Windows version is supported
func (c *WindowsCollector) isOSSupported(version string) bool {
	if version == "" {
		return false
	}

	// Parse major version (e.g., "10.0.19045" -> 10)
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return false
	}

	majorVersion := parseInt(parts[0])

	// Support Windows 10 and later
	return majorVersion >= 10
}
