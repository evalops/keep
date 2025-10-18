package main

import (
	"context"
	"log"
	"time"

	"github.com/EvalOps/keep/services/inventory/server"
)

func main() {
	cfg := server.Config{
		Addr:      getenv("INVENTORY_ADDR", ":8080"),
		DSN:       getenv("INVENTORY_DSN", "postgres://postgres:postgres@postgres:5432/keep?sslmode=disable"),
		MigDir:    getenv("INVENTORY_MIG_DIR", "/migrations"),
		TLSCert:   getenv("INVENTORY_TLS_CERT", ""),
		TLSKey:    getenv("INVENTORY_TLS_KEY", ""),
		AuthzJWKS: getenv("AUTHZ_JWKS_URL", ""),
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
