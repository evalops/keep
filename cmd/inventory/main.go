package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/EvalOps/keep/pkg/logging"
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
	logging.Initialize(defaultServiceName, envOrDefault("LOG_LEVEL", "info"))
	logger := logging.NewServiceLogger("cmd")

	var err error
	// Initialize secret management
	secretHelper := secrets.NewHelperFromEnv()
	secretHelper.LogSecretSource()

	// Load database configuration from secrets
	dbConfig := secretHelper.LoadDatabaseConfig()
	dsn, err := secrets.BuildDSN(dbConfig)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to build inventory DSN")
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
		logger.Warn().Err(err).Msg("inventory telemetry initialization failed")
	}

	srv, err := serverpkg.NewServer(cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize inventory server")
	}

	if err := srv.Start(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Fatal().Err(err).Msg("inventory server exited with error")
		}
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
