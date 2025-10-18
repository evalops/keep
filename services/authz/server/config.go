package server

import "time"

type Config struct {
	HTTPAddr        string
	GRPCAddr        string
	TLSCertPath     string
	TLSKeyPath      string
	RootCAPath      string
	GoogleClientID  string
	OPAURL          string
	InventoryAPI    string
	DeviceCertHours time.Duration
}
