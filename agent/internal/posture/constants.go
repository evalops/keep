package posture

const (
	UnknownValue         = "Unknown"
	UnknownService       = "unknown"
	emptyString          = ""
	newline              = "\n"
	colonSeparator       = ":"
	spaceSeparator       = " "
	minPartsTriple       = 3
	keyValueParts        = 2
	macOSVersionKey      = "System Version:"
	macOSKernelKey       = "Kernel Version:"
	macOSFirewallService = "pf"
	macOSFirewallEnabled = "1"
	macOSFirewallStealth = "2"
	macOSScreenPassword  = "askForPassword"
	macOSScreenDelay     = "askForPasswordDelay"
	macOSSleepKeyword    = "sleep"
	macOSUpdateNoNew     = "no new software available"
	macOSUpdateNoUpdates = "no updates available"
	macOSFileVaultOn     = "filevault is on"
	macOSPasswordEnabled = "1"

	StatusHealthy   = "healthy"
	StatusCompliant = "compliant"
	StatusWarning   = "warning"
	StatusCritical  = "critical"

	TrustBonusOS         = 20
	TrustBonusFirewall   = 25
	TrustBonusAntiVirus  = 15
	TrustBonusUpdate     = 20
	TrustBonusEncrypted  = 15
	TrustBonusScreenLock = 5

	TrustThresholdHealthy   = 80
	TrustThresholdCompliant = 60
	TrustThresholdWarning   = 40
	DefaultRules            = 0
	RuleNamePrefix          = "Rule Name:"
	MinWindowsVersion       = 10
	MinMacOSVersion         = 12
	MinFirewallRules        = 3
	initialCapacity         = 0
)
