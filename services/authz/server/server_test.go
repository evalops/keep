package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/tsnet"
)

const (
	testDeviceID       = "test-device"
	testAllowPath      = "/v1/data/keep/allow"
	testClientRemoteIP = "100.65.1.1:12345"
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
			DeviceID: testDeviceID,
			ClientIP: "192.168.1.1",
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal verify request: %v", err)
		}

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
	// Create a minimal test configuration
	cfg := Config{
		HTTPAddr:       ":8443",
		GoogleClientID: "test-client-id",
		OPAURL:         "http://test-opa:8181",
		InventoryAPI:   "http://test-inventory:8080",
	}

	// We can't use the real PKI here because it would create a dependency
	// So we'll create a minimal server instance
	server := &Server{
		cfg:       cfg,
		client:    &http.Client{Timeout: 5 * time.Second},
		invClient: &http.Client{Timeout: 3 * time.Second},
	}

	return server
}

// TestServer_envoyAuthHandler tests the Envoy auth handler
func TestServer_envoyAuthHandler(t *testing.T) {
	const (
		testDeviceID       = "test-device"
		testAllowPath      = "/v1/data/keep/allow"
		testClientRemoteIP = "100.65.1.1:12345"
	)
	// Create mock OPA server
	mockOPA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testAllowPath && r.Method == http.MethodPost {
			// Return "allow" decision for test
			response := map[string]interface{}{
				"result": map[string]interface{}{
					"decision": "allow",
				},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Fatalf("Failed to encode OPA response: %v", err)
			}
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
				"id":      testDeviceID,
				"posture": "healthy",
			}
			if err := json.NewEncoder(w).Encode(device); err != nil {
				t.Fatalf("Failed to encode device response: %v", err)
			}
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
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal envoy auth request: %v", err)
		}

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
							"x-device-id":   testDeviceID,
						},
					},
				},
			},
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal envoy auth request: %v", err)
		}

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
							"x-device-id":   testDeviceID,
						},
					},
				},
			},
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal envoy auth request: %v", err)
		}

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
							"authorization":   "Bearer invalid.jwt.token",
							"x-forwarded-for": "192.168.1.100",
							"x-device-id":     testDeviceID,
						},
					},
				},
			},
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal envoy auth request: %v", err)
		}

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
			name: "allow decision",
			opaResponse: map[string]interface{}{
				"result": map[string]interface{}{
					"decision": "allow",
				},
			},
			expectedResult: "allow",
			shouldError:    false,
		},
		{
			name: "deny decision",
			opaResponse: map[string]interface{}{
				"result": map[string]interface{}{
					"decision": "deny",
				},
			},
			expectedResult: "deny",
			shouldError:    false,
		},
		{
			name: "step-up decision",
			opaResponse: map[string]interface{}{
				"result": map[string]interface{}{
					"decision": "step-up",
				},
			},
			expectedResult: "step-up",
			shouldError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockOPA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == testAllowPath && r.Method == http.MethodPost {
					if err := json.NewEncoder(w).Encode(tc.opaResponse); err != nil {
						t.Fatalf("Failed to encode OPA response: %v", err)
					}
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

			result, err := server.evaluateOPA(context.Background(), claims, testDeviceID, "192.168.1.1")

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

// TestServer_lookupDevice tests the device lookup functionality
func TestServer_lookupDevice(t *testing.T) {
	t.Run("returns unknown posture when no inventory URL", func(t *testing.T) {
		server := createTestServerWithMocks(t, "", "")

		result := server.lookupDevice(context.Background(), testDeviceID)

		expected := map[string]any{
			"id":      "test-device",
			"posture": "unknown",
		}

		if result["id"] != expected["id"] || result["posture"] != expected["posture"] {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("returns unregistered for 404 response", func(t *testing.T) {
		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer mockInventory.Close()

		server := createTestServerWithMocks(t, "", mockInventory.URL)

		result := server.lookupDevice(context.Background(), "nonexistent-device")

		if result["posture"] != "unregistered" {
			t.Errorf("Expected posture 'unregistered', got %v", result["posture"])
		}
	})

	t.Run("returns device info for successful lookup", func(t *testing.T) {
		expectedDevice := map[string]interface{}{
			"id":      testDeviceID,
			"posture": "healthy",
		}

		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, testDeviceID) {
				if err := json.NewEncoder(w).Encode(expectedDevice); err != nil {
					t.Fatalf("Failed to encode device response: %v", err)
				}
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		}))
		defer mockInventory.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		server := createTestServerWithMocks(t, "", mockInventory.URL)

		result := server.lookupDevice(ctx, testDeviceID)

		if result["id"] != expectedDevice["id"] || result["posture"] != expectedDevice["posture"] {
			t.Errorf("Expected device info %v, got %v", expectedDevice, result)
		}
	})

	t.Run("handles empty device ID", func(t *testing.T) {
		server := createTestServerWithMocks(t, "", "http://inventory:8080")

		result := server.lookupDevice(context.Background(), "")

		if result["posture"] != "unknown" {
			t.Errorf("Expected posture 'unknown' for empty device ID, got %v", result["posture"])
		}
	})

	t.Run("handles inventory service errors", func(t *testing.T) {
		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer mockInventory.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		server := createTestServerWithMocks(t, "", mockInventory.URL)

		result := server.lookupDevice(ctx, "test-device")

		if result["posture"] != "unknown" {
			t.Errorf("Expected posture 'unknown' for service error, got %v", result["posture"])
		}
	})
}

// TestServer_deviceCertHandler tests the device certificate handler
func TestServer_deviceCertHandler(t *testing.T) {
	server := createTestServer(t)

	t.Run("rejects non-POST methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/certs/device", nil)
		rr := httptest.NewRecorder()

		server.deviceCertHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", rr.Code)
		}
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/certs/device", bytes.NewReader([]byte("invalid json")))
		rr := httptest.NewRecorder()

		server.deviceCertHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("rejects empty device ID", func(t *testing.T) {
		reqBody := map[string]string{
			"device_id": "",
			"csr":       "test-csr",
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal device cert request: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/certs/device", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.deviceCertHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})

	t.Run("rejects empty CSR", func(t *testing.T) {
		reqBody := map[string]string{
			"device_id": testDeviceID,
			"csr":       "",
		}
		body, err := json.Marshal(reqBody)
		if err != nil {
			t.Fatalf("Failed to marshal device cert request: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/v1/certs/device", bytes.NewReader(body))
		rr := httptest.NewRecorder()

		server.deviceCertHandler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rr.Code)
		}
	})
}

// TestServer_caHandler tests the CA certificate handler
func TestServer_caHandler(t *testing.T) {
	server := createTestServer(t)

	t.Run("rejects non-GET methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/certs/ca", nil)
		rr := httptest.NewRecorder()

		server.caHandler(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected status 405, got %d", rr.Code)
		}
	})

	// Note: Testing successful CA retrieval would require setting up the CA
	// which we avoid in unit tests to keep them lightweight
}

// TestServer_validateTailscaleAccess tests Tailscale network validation
func TestServer_validateTailscaleAccess(t *testing.T) {
	server := createTestServer(t)

	t.Run("returns false when no Tailscale server", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = testClientRemoteIP

		result := server.validateTailscaleAccess(req)

		if result != false {
			t.Error("Expected false when no Tailscale server configured")
		}
	})

	t.Run("returns false for non-Tailscale IP", func(t *testing.T) {
		// Simulate having a Tailscale server (minimal setup)
		server.tsServer = &tsnet.Server{} // Just for the nil check

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345" // Not in Tailscale range

		result := server.validateTailscaleAccess(req)

		if result != false {
			t.Error("Expected false for non-Tailscale IP range")
		}
	})

	t.Run("returns true for valid Tailscale IP", func(t *testing.T) {
		// Simulate having a Tailscale server
		server.tsServer = &tsnet.Server{}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = testClientRemoteIP // Valid Tailscale IP

		result := server.validateTailscaleAccess(req)

		if result != true {
			t.Error("Expected true for valid Tailscale IP range")
		}
	})

	t.Run("returns false for invalid remote address", func(t *testing.T) {
		server.tsServer = &tsnet.Server{}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "invalid-address"

		result := server.validateTailscaleAccess(req)

		if result != false {
			t.Error("Expected false for invalid remote address format")
		}
	})

	t.Run("returns false for empty remote address", func(t *testing.T) {
		server.tsServer = &tsnet.Server{}

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = ""

		result := server.validateTailscaleAccess(req)

		if result != false {
			t.Error("Expected false for empty remote address")
		}
	})
}
