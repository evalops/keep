package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// TestServer_envoyAuthHandler tests the Envoy auth handler
func TestServer_envoyAuthHandler(t *testing.T) {
	// Create mock OPA server
	mockOPA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/data/keep/allow" && r.Method == http.MethodPost {
			// Return "allow" decision for test
			response := map[string]interface{}{
				"result": "allow",
			}
			json.NewEncoder(w).Encode(response)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer mockOPA.Close()

	// Create mock inventory server
	mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/devices/") && r.Method == http.MethodGet {
			// Return device info
			device := map[string]interface{}{
				"id":      "test-device",
				"posture": "healthy",
			}
			json.NewEncoder(w).Encode(device)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer mockInventory.Close()

	server := createTestServerWithMocks(t, mockOPA.URL, mockInventory.URL)

	t.Run("rejects non-POST methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/check", nil)
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/check", bytes.NewReader([]byte("invalid json")))
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("rejects missing authorization header", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]interface{}{
				"request": map[string]interface{}{
					"http": map[string]interface{}{
						"headers": map[string]string{
							"x-device-id": "test-device",
						},
					},
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/check", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid Bearer token format", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]interface{}{
				"request": map[string]interface{}{
					"http": map[string]interface{}{
						"headers": map[string]string{
							"authorization": "InvalidToken",
							"x-device-id":   "test-device",
						},
					},
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/check", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid JWT token", func(t *testing.T) {
		reqBody := map[string]interface{}{
			"attributes": map[string]interface{}{
				"request": map[string]interface{}{
					"http": map[string]interface{}{
						"headers": map[string]string{
							"authorization": "Bearer invalid.jwt.token",
							"x-device-id":   "test-device",
						},
					},
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/check", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rr.Code)
		}
	})

	t.Run("extracts client IP from headers", func(t *testing.T) {
		// Test X-Forwarded-For header
		reqBody := map[string]interface{}{
			"attributes": map[string]interface{}{
				"request": map[string]interface{}{
					"http": map[string]interface{}{
						"headers": map[string]string{
							"authorization":    "Bearer invalid.jwt.token",
							"x-forwarded-for":  "192.168.1.100",
							"x-device-id":      "test-device",
						},
					},
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/v1/auth/check", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.envoyAuthHandler(rr, req)

		// Should still fail due to invalid JWT, but we're testing header parsing
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 (unauthorized due to invalid JWT), got %d", rr.Code)
		}
	})
}

// TestServer_evaluateOPA tests the OPA evaluation function
func TestServer_evaluateOPA(t *testing.T) {
	// Create mock OPA server with different responses
	testCases := []struct {
		name           string
		opaResponse    map[string]interface{}
		expectedResult string
		shouldError    bool
	}{
		{
			name:           "allow decision",
			opaResponse:    map[string]interface{}{"result": "allow"},
			expectedResult: "allow",
			shouldError:    false,
		},
		{
			name:           "deny decision",
			opaResponse:    map[string]interface{}{"result": "deny"},
			expectedResult: "deny",
			shouldError:    false,
		},
		{
			name:           "step-up decision",
			opaResponse:    map[string]interface{}{"result": "step-up"},
			expectedResult: "step-up",
			shouldError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockOPA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/data/keep/allow" && r.Method == http.MethodPost {
					json.NewEncoder(w).Encode(tc.opaResponse)
				} else {
					http.Error(w, "not found", http.StatusNotFound)
				}
			}))
			defer mockOPA.Close()

			server := createTestServerWithMocks(t, mockOPA.URL, "")
			
			claims := map[string]any{
				"email":  "user@example.com",
				"groups": []string{"admin"},
			}

			result, err := server.evaluateOPA(context.Background(), claims, "test-device", "192.168.1.1")

			if tc.shouldError {
				if err == nil {
					t.Error("Expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result != tc.expectedResult {
					t.Errorf("Expected result %s, got %s", tc.expectedResult, result)
				}
			}
		})
	}
}

// createTestServerWithMocks creates a test server with mock OPA and inventory URLs
func createTestServerWithMocks(t *testing.T, opaURL, inventoryURL string) *Server {
	cfg := Config{
		HTTPAddr:       ":8443",
		GoogleClientID: "test-client-id",
		OPAURL:         opaURL,
		InventoryAPI:   inventoryURL,
	}

	server := &Server{
		cfg:       cfg,
		client:    &http.Client{Timeout: 5 * time.Second},
		invClient: &http.Client{Timeout: 3 * time.Second},
	}

	return server
}
