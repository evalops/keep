package server

import "time"

type Config struct {
	HTTPAddr            string
	GRPCAddr            string
	TLSCertPath         string
	TLSKeyPath          string
	RootCAPath          string
	GoogleClientID      string
	OPAURL              string
	InventoryAPI        string
	InventoryClientCert string // Client certificate for mTLS to inventory service
	InventoryClientKey  string // Client private key for mTLS to inventory service
	InventoryCA         string // CA certificate for inventory service validation

	// Vouch integration config
	VouchEnabled        bool
	VouchBaseURL        string
	VouchAPIKey         string
	VouchTimeout        time.Duration
	VouchCacheTTL       time.Duration
	VouchMaxEntries     int
	VouchRetryEnabled   bool
	VouchRetryAttempts  int
	VouchCircuitBreaker bool

	TailscaleAuthKey    string
	TailscaleHostname   string
	TailscaleListenAddr string
	TailscaleAPIKey     string
	TailscaleTailnet    string
	MFAServiceURL       string
	TelemetryEndpoint   string
	TelemetryEnv        string
	DeviceCertHours     time.Duration
	RequestTimeout      time.Duration
	RetryMaxElapsed     time.Duration
	RetryMaxAttempts    int
	TelemetryInsecure   bool
}
