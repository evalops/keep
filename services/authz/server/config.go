package server

import "time"

type Config struct {
	// time.Duration fields first (8 bytes each)
	VouchTimeout    time.Duration
	VouchCacheTTL   time.Duration
	DeviceCertHours time.Duration
	RequestTimeout  time.Duration
	RetryMaxElapsed time.Duration

	// int fields next (4/8 bytes each)
	VouchMaxEntries    int
	VouchRetryAttempts int
	RetryMaxAttempts   int

	// bool fields (1 byte each)
	VouchEnabled        bool
	VouchRetryEnabled   bool
	VouchCircuitBreaker bool
	TelemetryInsecure   bool

	// string fields last (pointers - 8 bytes each + variable size)
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
	VouchBaseURL        string
	VouchAPIKey         string
	TailscaleAuthKey    string
	TailscaleHostname   string
	TailscaleListenAddr string
	TailscaleAPIKey     string
	TailscaleTailnet    string
	MFAServiceURL       string
	TelemetryEndpoint   string
	TelemetryEnv        string
}
