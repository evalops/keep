package main

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/pkg/secrets"
	"github.com/EvalOps/keep/pkg/telemetry"
	serverpkg "github.com/EvalOps/keep/services/inventory/server"
)

const (
	flagValueTrue      = "true"
	defaultAppEnv      = "development"
	defaultRequireMTLS = "false"
	defaultShutdown    = 5 * time.Second
	defaultServiceName = "inventory"
)

func main() {
	var err error
	// Initialize secret management
	secretHelper := secrets.NewHelperFromEnv()
	secretHelper.LogSecretSource()

	// Load database configuration from secrets
	dbConfig := secretHelper.LoadDatabaseConfig()
	dsn, err := secrets.BuildDSN(dbConfig)
	if err != nil {
		log.Fatalf("inventory dsn: %v", err)
	}

	// Load TLS configuration from secrets
	tlsConfig := secretHelper.LoadTLSConfig("INVENTORY")

	cfg := serverpkg.Config{
		Addr:        envOrDefault("INVENTORY_ADDR", ":8080"),
		DSN:         envOrDefault("INVENTORY_DSN", dsn),
		TLSCert:     secretHelper.GetOrDefault("INVENTORY_TLS_CERT", tlsConfig["INVENTORY_TLS_CERT"]),
		TLSKey:      secretHelper.GetOrDefault("INVENTORY_TLS_KEY", tlsConfig["INVENTORY_TLS_KEY"]),
		ClientCA:    secretHelper.GetOrDefault("INVENTORY_CLIENT_CA", tlsConfig["INVENTORY_CLIENT_CA"]),
		AuthzJWKS:   envOrDefault("AUTHZ_JWKS_URL", ""),
		Shutdown:    defaultShutdown,
		RequireMTLS: envOrDefault("INVENTORY_REQUIRE_MTLS", defaultRequireMTLS) == flagValueTrue,
	}

	ctx := context.Background()
	telemetryCfg := telemetry.Config{
		Endpoint:    os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		Insecure:    os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == flagValueTrue,
		ServiceName: defaultServiceName,
		Environment: envOrDefault("APP_ENV", defaultAppEnv),
	}

	if err = telemetry.Init(ctx, telemetryCfg); err != nil {
		log.Printf("telemetry init failed: %v", err)
	}

	srv, err := serverpkg.NewServer(cfg)
	if err != nil {
		log.Fatalf("init inventory: %v", err)
	}

	if err := srv.Start(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Fatalf("inventory exit: %v", err)
		}
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
