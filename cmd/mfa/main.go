package main

import (
	"context"
	"os"
	"time"

	"github.com/EvalOps/keep/pkg/logging"
	"github.com/EvalOps/keep/services/mfa"
)

const (
	defaultAddr       = ":8445"
	defaultCodeDigits = 6
)

func main() {
	logging.Initialize("mfa", getenv("LOG_LEVEL", "info"))
	logger := logging.NewServiceLogger("cmd")

	addr := getenv("MFA_LISTEN_ADDR", defaultAddr)
	sessionTimeout := getenvDuration("MFA_SESSION_TIMEOUT", 5*time.Minute)

	cfg := mfa.Config{
		Addr:           addr,
		SessionTimeout: sessionTimeout,
		CodeLength:     defaultCodeDigits,
	}

	server := mfa.New(cfg)

	logger.Info().Str("addr", addr).Msg("starting MFA service")
	if err := server.Start(context.Background()); err != nil {
		logger.Fatal().Err(err).Msg("MFA service failed")
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}
