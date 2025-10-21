package server

import "time"

type Config struct {
	InventoryClientCert string
	InventoryClientKey  string
	TelemetryEnv        string
	TelemetryEndpoint   string
	MFAServiceURL       string
	TailscaleTailnet    string
	TailscaleAPIKey     string
	TailscaleListenAddr string
	HTTPAddr            string
	GRPCAddr            string
	TLSCertPath         string
	TLSKeyPath          string
	RootCAPath          string
	GoogleClientID      string
	OPAURL              string
	InventoryAPI        string
	TailscaleHostname   string
	InventoryCA         string
	TailscaleAuthKey    string
	VouchBaseURL        string
	VouchAPIKey         string
	VouchTimeout        time.Duration
	VouchCacheTTL       time.Duration
	RetryMaxAttempts    int
	VouchRetryAttempts  int
	VouchMaxEntries     int
	RetryMaxElapsed     time.Duration
	RequestTimeout      time.Duration
	DeviceCertHours     time.Duration
	VouchEnabled        bool
	VouchRetryEnabled   bool
	VouchCircuitBreaker bool
	TelemetryInsecure   bool
}
