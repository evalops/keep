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
	DeviceCertHours     time.Duration
	TailscaleAuthKey    string
	TailscaleHostname   string
	TailscaleListenAddr string
	TailscaleAPIKey     string
	TailscaleTailnet    string
	MFAServiceURL       string
}
