package main

import (
	"context"
	"log"
	"os"
	"time"

	serverpkg "github.com/EvalOps/keep/services/inventory/server"
)

func main() {
	cfg := serverpkg.Config{
		Addr:        envOrDefault("INVENTORY_ADDR", ":8080"),
		DSN:         envOrDefault("INVENTORY_DSN", "postgres://postgres:postgres@postgres:5432/keep?sslmode=disable"),
		TLSCert:     envOrDefault("INVENTORY_TLS_CERT", ""),
		TLSKey:      envOrDefault("INVENTORY_TLS_KEY", ""),
		ClientCA:    envOrDefault("INVENTORY_CLIENT_CA", ""),
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
