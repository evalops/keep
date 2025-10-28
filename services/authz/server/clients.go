package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/pkg/retry"
	"github.com/EvalOps/keep/pkg/telemetry"
	"github.com/EvalOps/keep/pkg/vouch"
)

func configureInventoryClient(cfg Config) (*http.Client, error) {
	logger := logging.NewServiceLogger("inventory-client")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if cfg.InventoryClientCert != emptyString && cfg.InventoryClientKey != emptyString {
		cert, err := tls.LoadX509KeyPair(cfg.InventoryClientCert, cfg.InventoryClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}

		transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
		logger.Info().Msg("configured mTLS client certificate for inventory service")
	}

	if cfg.InventoryCA != emptyString {
		caCert, err := os.ReadFile(cfg.InventoryCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read inventory CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse inventory CA certificate")
		}

		transport.TLSClientConfig.RootCAs = caCertPool
		logger.Info().Msg("configured custom CA for inventory service validation")
	}

	return telemetry.WrapClient(&http.Client{
		Timeout:   defaultInventoryTimeout,
		Transport: transport,
	}), nil
}

func configureVouchClient(cfg Config) (vouch.DevicePostureClient, error) {
	vouchConfig := vouch.Config{
		BaseURL:    cfg.VouchBaseURL,
		APIKey:     cfg.VouchAPIKey,
		Timeout:    cfg.VouchTimeout,
		CacheTTL:   cfg.VouchCacheTTL,
		MaxEntries: cfg.VouchMaxEntries,
	}

	if vouchConfig.Timeout == zeroValue {
		vouchConfig.Timeout = defaultVouchTimeout
	}
	if vouchConfig.CacheTTL == zeroValue {
		vouchConfig.CacheTTL = defaultVouchCacheTTL
	}
	if vouchConfig.MaxEntries == zeroValue {
		vouchConfig.MaxEntries = defaultVouchMaxEntries
	}

	if cfg.VouchRetryEnabled {
		vouchConfig.RetryConfig = retry.Config{
			MaxAttempts:     cfg.VouchRetryAttempts,
			InitialInterval: defaultInitialInterval,
			Multiplier:      defaultRetryMultiplier,
			MaxInterval:     defaultMaxInterval,
		}
		if vouchConfig.RetryConfig.MaxAttempts == zeroValue {
			vouchConfig.RetryConfig.MaxAttempts = defaultVouchRetryAttempts
		}
	}

	vouchConfig.CircuitBreaker.Enabled = cfg.VouchCircuitBreaker
	if vouchConfig.CircuitBreaker.Enabled {
		vouchConfig.CircuitBreaker.FailureThreshold = defaultVouchFailureThresh
		vouchConfig.CircuitBreaker.TimeoutSeconds = defaultVouchCircuitTimeout
	}

	client, err := vouch.NewClient(vouchConfig)
	if err != nil {
		return nil, fmt.Errorf("create vouch client: %w", err)
	}

	return client, nil
}
