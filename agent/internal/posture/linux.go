package posture

import (
	"runtime"
	"strings"
)

const (
	// OS constants
	linuxOSName = "Linux"
	
	// Service names
	ufwService      = "ufw"
	iptablesService = "iptables"
	
	// Command keywords
	ufwStatusActive = "status: active"
	cryptoLUKS      = "crypto_luks"
	cryptKeyword    = "crypt"
	trueKeyword     = "true"
	
	// Firewall rule keywords
	allowKeyword  = "ALLOW"
	denyKeyword   = "DENY"
	acceptKeyword = "ACCEPT"
	dropKeyword   = "DROP"
	rejectKeyword = "REJECT"
	
	// Table headers to ignore
	chainPrefix  = "Chain"
	targetPrefix = "target"
	numPrefix    = "num"
)

var (
	// Common Linux antivirus software
	linuxAntivirusSoftware = []string{"clamav", "sophos", "avast", "bitdefender", "eset"}
)

// LinuxCollector collects device posture on Linux systems
type LinuxCollector struct{}

// CollectPosture collects device posture information on Linux
func (c *LinuxCollector) CollectPosture() (*DevicePosture, error) {
	posture := &DevicePosture{
		OS: OperatingSystem{
			Name: linuxOSName,
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
		posture.Firewall = FirewallStatus{Enabled: false, Service: UnknownService}
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

// collectOSInfo gathers Linux OS information
func (c *LinuxCollector) collectOSInfo(os *OperatingSystem) error {
	// Read /etc/os-release
	if fileExists("/etc/os-release") {
		content, err := readFile("/etc/os-release")
		if err != nil {
			return err
		}

		osInfo := parseKeyValue(string(content))
		if name, ok := osInfo["PRETTY_NAME"]; ok {
			os.Name = name
		} else if name, ok := osInfo["NAME"]; ok {
			os.Name = name
		}

		if version, ok := osInfo["VERSION"]; ok {
			os.Version = version
		} else if version, ok := osInfo["VERSION_ID"]; ok {
			os.Version = version
		}

		if build, ok := osInfo["BUILD_ID"]; ok {
			os.Build = build
		}
	}

	// Get kernel version
	if kernel, err := runCommand("uname", "-r"); err == nil {
		os.Kernel = kernel
	}

	// Check if OS is supported (basic check for major distros)
	os.Supported = c.isOSSupported(os.Name)

	return nil
}

// collectFirewallStatus checks UFW and iptables status
func (c *LinuxCollector) collectFirewallStatus(fw *FirewallStatus) error {
	// Check UFW first
	if checkUFW(fw) {
		return nil
	}

	// Fallback to iptables
	return c.checkIptables(fw)
}

// checkUFW checks Ubuntu UFW firewall status
func checkUFW(fw *FirewallStatus) bool {
	output, err := runCommand("ufw", "status")
	if err != nil {
		return false
	}

	fw.Service = ufwService
	fw.Enabled = strings.Contains(strings.ToLower(output), ufwStatusActive)

	// Count rules (simplified)
	lines := strings.Split(output, "\n")
	ruleCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Status:") &&
			!strings.HasPrefix(line, "To") && !strings.HasPrefix(line, "--") {
			if strings.Contains(line, allowKeyword) || strings.Contains(line, denyKeyword) {
				ruleCount++
			}
		}
	}
	fw.Rules = ruleCount

	return true
}

// checkIptables checks iptables firewall status
func (c *LinuxCollector) checkIptables(fw *FirewallStatus) error {
	output, err := runCommand("iptables", "-L")
	if err != nil {
		fw.Enabled = false
		fw.Service = "none"
		return err
	}

	fw.Service = iptablesService
	// If iptables returns without error and has rules, consider it enabled
	lines := strings.Split(output, "\n")
	ruleCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, chainPrefix) &&
			!strings.HasPrefix(line, targetPrefix) && !strings.HasPrefix(line, numPrefix) {
			if strings.Contains(line, acceptKeyword) || strings.Contains(line, dropKeyword) ||
				strings.Contains(line, rejectKeyword) {
				ruleCount++
			}
		}
	}

	fw.Rules = ruleCount
	fw.Enabled = ruleCount > MinFirewallRules // More than default rules

	return nil
}

// checkAntiVirus checks for antivirus software
func (c *LinuxCollector) checkAntiVirus() bool {
	// Check for common Linux antivirus solutions
	antivirusSoftware := linuxAntivirusSoftware

	for _, av := range antivirusSoftware {
		if _, err := runCommand("which", av); err == nil {
			return true
		}

		// Check if service is running
		if _, err := runCommand("systemctl", "is-active", av); err == nil {
			return true
		}
	}

	return false
}

// checkSystemUpdated checks if system is up to date
func (c *LinuxCollector) checkSystemUpdated() bool {
	// Check for pending updates (works on Debian/Ubuntu systems)
	output, err := runCommand("apt", "list", "--upgradable")
	if err == nil {
		lines := strings.Split(output, "\n")
		// If only header line, no updates available
		return len(lines) <= 2
	}

	// Try yum/dnf for Red Hat systems
	output, err = runCommand("yum", "check-update")
	if err != nil {
		// Exit code 0 means no updates, 100 means updates available
		return true
	}

	return strings.TrimSpace(output) == ""
}

// checkDiskEncryption checks if disk encryption is enabled
func (c *LinuxCollector) checkDiskEncryption() bool {
	// Check for LUKS encrypted devices
	output, err := runCommand("lsblk", "-f")
	if err != nil {
		return false
	}

	lowerOutput := strings.ToLower(output)
	return strings.Contains(lowerOutput, cryptoLUKS) ||
		strings.Contains(lowerOutput, cryptKeyword)
}

// checkScreenLock checks if screen lock is configured
func (c *LinuxCollector) checkScreenLock() bool {
	// Check GNOME settings
	if output, err := runCommand("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled"); err == nil {
		return strings.Contains(strings.ToLower(output), trueKeyword)
	}

	// Check KDE settings
	if fileExists("/home/" + getUserName() + "/.config/kscreenlockerrc") {
		return true
	}

	// Default to false if can't determine
	return false
}

// isOSSupported checks if the OS version is supported
func (c *LinuxCollector) isOSSupported(osName string) bool {
	supportedDistros := []string{
		"ubuntu", "debian", "centos", "rhel", "fedora",
		"suse", "opensuse", "arch", "mint", "elementary",
	}

	osNameLower := strings.ToLower(osName)
	for _, distro := range supportedDistros {
		if strings.Contains(osNameLower, distro) {
			return true
		}
	}

	return false
}

// getUserName gets the current username
func getUserName() string {
	if output, err := runCommand("whoami"); err == nil {
		return strings.TrimSpace(output)
	}
	return UnknownService
}
