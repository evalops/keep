package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/pkg/secrets"
	serverpkg "github.com/EvalOps/keep/services/inventory/server"
)

func main() {
	// Initialize secret management
	secretHelper := secrets.NewHelperFromEnv()
	secretHelper.LogSecretSource()

	// Load database configuration from secrets
	dbConfig := secretHelper.LoadDatabaseConfig()
	dsn := secretHelper.BuildDSN(dbConfig)

	// Load TLS configuration from secrets
	tlsConfig := secretHelper.LoadTLSConfig("INVENTORY")

	cfg := serverpkg.Config{
		Addr:        envOrDefault("INVENTORY_ADDR", ":8080"),
		DSN:         envOrDefault("INVENTORY_DSN", dsn),
		TLSCert:     secretHelper.GetOrDefault("INVENTORY_TLS_CERT", tlsConfig["INVENTORY_TLS_CERT"]),
		TLSKey:      secretHelper.GetOrDefault("INVENTORY_TLS_KEY", tlsConfig["INVENTORY_TLS_KEY"]),
		ClientCA:    secretHelper.GetOrDefault("INVENTORY_CLIENT_CA", tlsConfig["INVENTORY_CLIENT_CA"]),
		AuthzJWKS:   envOrDefault("AUTHZ_JWKS_URL", ""),
		Shutdown:    5 * time.Second,
		RequireMTLS: envOrDefault("INVENTORY_REQUIRE_MTLS", "false") == "true",
	}

	srv, err := serverpkg.NewServer(cfg)
	if err != nil {
		log.Fatalf("init inventory: %v", err)
	}

	if err := srv.Start(context.Background()); err != nil {
		log.Fatalf("inventory exit: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
