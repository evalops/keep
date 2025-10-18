package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestServer_healthHandler tests the health endpoint
func TestServer_healthHandler(t *testing.T) {
	server := createTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	server.healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", response["status"])
	}

	if _, exists := response["tailscale"]; !exists {
		t.Error("Expected tailscale info in response")
	}
}

// TestServer_verifyHandler tests the verify endpoint
func TestServer_verifyHandler(t *testing.T) {
	server := createTestServer(t)

	t.Run("rejects non-POST methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/verify", nil)
		rr := httptest.NewRecorder()

		server.verifyHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify", bytes.NewReader([]byte("invalid json")))
		rr := httptest.NewRecorder()

		server.verifyHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		reqBody := verifyRequest{
			Token:    "invalid.jwt.token",
			DeviceID: "test-device",
			ClientIP: "192.168.1.1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.verifyHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})
}

// TestServer_tailscaleStatusHandler tests the Tailscale status endpoint
func TestServer_tailscaleStatusHandler(t *testing.T) {
	server := createTestServer(t)

	t.Run("returns JSON status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/tailscale/status", nil)
		rr := httptest.NewRecorder()

		server.tailscaleStatusHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rr.Code)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if enabled, ok := response["enabled"].(bool); !ok || enabled != false {
			t.Errorf("Expected enabled=false (no Tailscale configured), got %v", response["enabled"])
		}
	})

	t.Run("rejects non-GET methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/tailscale/status", nil)
		rr := httptest.NewRecorder()

		server.tailscaleStatusHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", rr.Code)
		}
	})
}

// createTestServer creates a minimal server for testing
func createTestServer(t *testing.T) *Server {
	tmpDir := t.TempDir()
	
	// Create a minimal test configuration
	cfg := Config{
		HTTPAddr:       ":8443",
		GoogleClientID: "test-client-id",
		OPAURL:         "http://test-opa:8181",
		InventoryAPI:   "http://test-inventory:8080",
	}

	// Create test CA for the server
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	// We can't use the real PKI here because it would create a dependency
	// So we'll create a minimal server instance
	server := &Server{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		invClient: &http.Client{Timeout: 3 * time.Second},
	}

	return server
}
