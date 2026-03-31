package main

import (
	"context"
	"os"
	"time"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/services/inventory/server"
)

const (
	defaultBindAddr    = ":8080"
	defaultDSN         = "postgres://postgres:postgres@postgres:5432/keep?sslmode=disable" // #nosec G101 -- dev-only default, overridden by env var in production
	defaultTLSCert     = ""
	defaultTLSKey      = ""
	defaultAuthzJWKS   = ""
	defaultShutdownDur = 5 * time.Second
)

func main() {
	logging.Initialize("inventory-service", envDefault("LOG_LEVEL", "info"))
	logger := logging.NewServiceLogger("bootstrap")

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
		logger.Fatal().Err(err).Msg("failed to init inventory")
	}

	if err := srv.Start(context.Background()); err != nil {
		logger.Fatal().Err(err).Msg("inventory service exited")
	}
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {}
