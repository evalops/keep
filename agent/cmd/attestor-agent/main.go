package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EvalOps/keep/pkg/pki"
)

type registerRequest struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Posture   string `json:"posture"`
}

type certResponse struct {
	Certificate string `json:"certificate"`
}

func main() {
	var (
		deviceID      = flag.String("device-id", "", "Unique device identifier")
		inventoryURL  = flag.String("inventory-url", "http://localhost:8081", "Inventory service base URL")
		attestURL     = flag.String("authz-url", "http://localhost:8443", "Authz service base URL")
		keyPath       = flag.String("key", "./.keep/device.key", "Path to device private key")
		certPath      = flag.String("cert", "./.keep/device.crt", "Path to issued device certificate")
		caPath        = flag.String("ca", "./.keep/ca.pem", "Path to root CA (downloaded)")
		posture       = flag.String("posture", "healthy", "Initial device posture")
		refreshPeriod = flag.Duration("refresh", 15*time.Minute, "Certificate renewal interval")
	)
	flag.Parse()

	if *deviceID == "" {
		log.Fatal("--device-id is required")
	}

	priv := ensureKey(*keyPath)

	pubPEM, err := pki.PublicKeyPEM(priv)
	if err != nil {
		log.Fatalf("public key pem: %v", err)
	}

	if err := registerDevice(*inventoryURL, *deviceID, string(pubPEM), *posture); err != nil {
		log.Fatalf("register device: %v", err)
	}

	if err := obtainCertificate(*attestURL, priv, *deviceID, *certPath, *caPath); err != nil {
		log.Fatalf("obtain certificate: %v", err)
	}

	ctx := context.Background()
	ticker := time.NewTicker(*refreshPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := obtainCertificate(*attestURL, priv, *deviceID, *certPath, *caPath); err != nil {
				log.Printf("certificate refresh failed: %v", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func ensureKey(path string) *ecdsa.PrivateKey {
	if _, err := os.Stat(path); err == nil {
		key, err := pki.LoadSigningKey(path)
		if err != nil {
			log.Fatalf("load key: %v", err)
		}
		return key
	}
	key, err := pki.GenerateSigningKey(path)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	return key
}

func registerDevice(baseURL, id, publicKey, posture string) error {
	payload := registerRequest{ID: id, PublicKey: publicKey, Posture: posture}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("%s/v1/devices", strings.TrimSuffix(baseURL, "/")), "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("inventory register failed: %s", resp.Status)
	}
	return nil
}

func obtainCertificate(baseURL string, key *ecdsa.PrivateKey, deviceID, certPath, caPath string) error {
	csrPEM, err := pki.CreateCSR(key, deviceID)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"device_id": deviceID,
		"csr":       string(csrPEM),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("%s/v1/certs/device", strings.TrimSuffix(baseURL, "/")), "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("cert request failed: %s", resp.Status)
	}

	var cr certResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return err
	}

	if err := pki.WriteCertificate(certPath, []byte(cr.Certificate)); err != nil {
		return err
	}

	if _, err := os.Stat(caPath); err != nil {
		rawCA, err := downloadCA(baseURL)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(caPath, rawCA, 0o644); err != nil {
			return err
		}
	}

	return nil
}

func downloadCA(baseURL string) ([]byte, error) {
	resp, err := http.Get(fmt.Sprintf("%s/v1/certs/ca", strings.TrimSuffix(baseURL, "/")))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ca download failed: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}
