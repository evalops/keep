package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/services/mfa"
)

const (
	defaultAddr       = ":8445"
	defaultCodeDigits = 6
)

func main() {
	addr := getenv("MFA_LISTEN_ADDR", defaultAddr)
	sessionTimeout := getenvDuration("MFA_SESSION_TIMEOUT", 5*time.Minute)

	cfg := mfa.Config{
		Addr:           addr,
		SessionTimeout: sessionTimeout,
		CodeLength:     defaultCodeDigits,
	}

	server := mfa.New(cfg)

	log.Printf("Starting MFA service on %s", addr)
	if err := server.Start(context.Background()); err != nil {
		log.Fatalf("MFA service failed: %v", err)
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
