package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/EvalOps/keep/services/authz/server"
)

func main() {
	addr := getenv("AUTHZ_LISTEN_ADDR", ":8443")
	grpcAddr := getenv("AUTHZ_GRPC_ADDR", ":8444")
	certFile := getenv("AUTHZ_CERT_FILE", "")
	keyFile := getenv("AUTHZ_KEY_FILE", "")
	caFile := getenv("AUTHZ_CA_FILE", "")
	googleClientID := getenv("GOOGLE_CLIENT_ID", "")

	if googleClientID == "" {
		log.Fatal("GOOGLE_CLIENT_ID must be set")
	}

	srv, err := server.New(server.Config{
		HTTPAddr:        addr,
		GRPCAddr:        grpcAddr,
		TLSCertPath:     certFile,
		TLSKeyPath:      keyFile,
		RootCAPath:      caFile,
		GoogleClientID:  googleClientID,
		OPAURL:          getenv("OPA_URL", "http://opa:8181"),
		InventoryAPI:    getenv("INVENTORY_API", "http://inventory:8080"),
		DeviceCertHours: getenvDuration("DEVICE_CERT_HOURS", 4*time.Hour),
	})
	if err != nil {
		log.Fatalf("failed to create authz server: %v", err)
	}

	if err := srv.Start(context.Background()); err != nil {
		log.Fatalf("server exited: %v", err)
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
