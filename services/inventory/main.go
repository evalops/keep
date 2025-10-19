package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/services/inventory/server"
)

const (
	defaultBindAddr    = ":8080"
	defaultDSN         = "postgres://postgres:postgres@postgres:5432/keep?sslmode=disable"
	defaultTLSCert     = ""
	defaultTLSKey      = ""
	defaultAuthzJWKS   = ""
	defaultShutdownDur = 5 * time.Second
)

func main() {
	cfg := server.Config{
		Addr:      envDefault("INVENTORY_ADDR", defaultBindAddr),
		DSN:       envDefault("INVENTORY_DSN", defaultDSN),
		TLSCert:   envDefault("INVENTORY_TLS_CERT", defaultTLSCert),
		TLSKey:    envDefault("INVENTORY_TLS_KEY", defaultTLSKey),
		AuthzJWKS: envDefault("AUTHZ_JWKS_URL", defaultAuthzJWKS),
		Shutdown:  defaultShutdownDur,
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatalf("init inventory: %v", err)
	}

	if err := srv.Start(context.Background()); err != nil {
		log.Fatalf("inventory exit: %v", err)
	}
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {}
