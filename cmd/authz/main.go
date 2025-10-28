package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/secrets"
	"github.com/EvalOps/keep/services/authz/server"
)

const (
	emptyString           = ""
	defaultAuthzPort      = ":8443"
	defaultGRPCPort       = ":8444"
	defaultOPAURL         = "http://opa:8181"
	defaultInventoryURL   = "http://inventory:8080"
	defaultRootCACertPath = "/data/certs/keep-root.pem"
	defaultRootCAKeyPath  = "/data/certs/keep-root-key.pem"
)

func main() {
	logging.Initialize("authz", getenv("LOG_LEVEL", "info"))
	logger := logging.NewServiceLogger("cmd")

	// Initialize secret management
	secretHelper := secrets.NewHelperFromEnv()
	secretHelper.LogSecretSource()

	// Load API keys and tokens from secrets
	apiKeys := secretHelper.LoadAPIKeys()

	// Load TLS configuration from secrets
	tlsConfig := secretHelper.LoadTLSConfig("AUTHZ")

	addr := getenv("AUTHZ_LISTEN_ADDR", defaultAuthzPort)
	grpcAddr := getenv("AUTHZ_GRPC_ADDR", defaultGRPCPort)
	certFile := secretHelper.GetOrDefault("AUTHZ_CERT_FILE", tlsConfig["AUTHZ_TLS_CERT"])
	rootCAPath := secretHelper.GetOrDefault("AUTHZ_ROOT_CA_CERT", defaultRootCACertPath)
	rootCAKeyPath := secretHelper.GetOrDefault("AUTHZ_ROOT_CA_KEY", defaultRootCAKeyPath)
	googleClientID := secretHelper.GetOrDefault("GOOGLE_CLIENT_ID", apiKeys["GOOGLE_CLIENT_ID"])

	if googleClientID == "" {
		logger.Fatal().Msg("GOOGLE_CLIENT_ID must be set")
	}

	srv, err := server.New(server.Config{
		HTTPAddr:            addr,
		GRPCAddr:            grpcAddr,
		TLSCertPath:         certFile,
		TLSKeyPath:          rootCAKeyPath,
		RootCAPath:          rootCAPath,
		GoogleClientID:      googleClientID,
		OPAURL:              getenv("OPA_URL", defaultOPAURL),
		InventoryAPI:        getenv("INVENTORY_API", defaultInventoryURL),
		InventoryClientCert: secretHelper.GetOrDefault("AUTHZ_CLIENT_CERT", tlsConfig["AUTHZ_CLIENT_CERT"]),
		InventoryClientKey:  secretHelper.GetOrDefault("AUTHZ_CLIENT_KEY", tlsConfig["AUTHZ_CLIENT_KEY"]),
		InventoryCA:         secretHelper.GetOrDefault("AUTHZ_CA_CERT", tlsConfig["AUTHZ_CLIENT_CA"]),
		DeviceCertHours:     getenvDuration("DEVICE_CERT_HOURS", 4*time.Hour),
		TailscaleAuthKey:    secretHelper.GetOrDefault("TAILSCALE_AUTH_KEY", apiKeys["TAILSCALE_AUTH_KEY"]),
		TailscaleAPIKey:     secretHelper.GetOrDefault("TAILSCALE_API_KEY", apiKeys["TAILSCALE_API_KEY"]),
		MFAServiceURL:       getenv("MFA_SERVICE_URL", emptyString),
		TelemetryEndpoint:   getenv("TELEMETRY_ENDPOINT", emptyString),
		TelemetryInsecure:   getenv("TELEMETRY_INSECURE", emptyString) == "1",
		TelemetryEnv:        getenv("ENVIRONMENT", "development"),
		RequestTimeout:      getenvDuration("AUTHZ_REQUEST_TIMEOUT", 3*time.Second),
		RetryMaxAttempts:    getenvInt("AUTHZ_RETRY_ATTEMPTS", 3),
		RetryMaxElapsed:     getenvDuration("AUTHZ_RETRY_MAX_ELAPSED", 10*time.Second),
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create authz server")
	}

	ctx := context.Background()
	runErr := srv.Start(ctx)
	if runErr == nil {
		return
	}

	if !errors.Is(runErr, context.Canceled) {
		logger.Fatal().Err(runErr).Msg("authz server exited unexpectedly")
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != emptyString {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != emptyString {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != emptyString {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return def
}
