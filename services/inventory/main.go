package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/services/inventory/server"
)

func main() {
	cfg := server.Config{
		Addr:      envDefault("INVENTORY_ADDR", ":8080"),
		DSN:       envDefault("INVENTORY_DSN", "postgres://postgres:postgres@postgres:5432/keep?sslmode=disable"),
		TLSCert:   envDefault("INVENTORY_TLS_CERT", ""),
		TLSKey:    envDefault("INVENTORY_TLS_KEY", ""),
		AuthzJWKS: envDefault("AUTHZ_JWKS_URL", ""),
		Shutdown:  5 * time.Second,
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
