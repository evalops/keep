package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EvalOps/keep/agent/internal/posture"
)

const (
	testDeviceID    = "test-device"
	initialCapacity = 0
	pidFileMode     = 0o600
)

// mockPostureCollector implements the posture.Collector interface for testing
type mockPostureCollector struct {
	postureData *posture.DevicePosture
	shouldError bool
}

func (m *mockPostureCollector) CollectPosture() (*posture.DevicePosture, error) {
	if m.shouldError {
		return nil, &mockError{"mock posture collection error"}
	}
	return m.postureData, nil
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// TestService_New tests service creation
func TestService_New(t *testing.T) {
	t.Run("creates service with valid config", func(t *testing.T) {
		config := &Config{
			DeviceID:        testDeviceID,
			InventoryURL:    "http://localhost:8081",
			AttestURL:       "http://localhost:8443",
			KeyPath:         "/tmp/test.key",
			CertPath:        "/tmp/test.crt",
			CAPath:          "/tmp/ca.pem",
			RefreshPeriod:   time.Hour,
			PostureInterval: time.Minute * 5,
		}

		service := New(config)

		if service == nil {
			t.Fatal("Expected service, got nil")
		}

		if service.config.DeviceID != config.DeviceID {
			t.Errorf("Expected DeviceID %s, got %s", config.DeviceID, service.config.DeviceID)
		}

		if service.collector == nil {
			t.Error("Expected collector to be initialized")
		}
	})
}

// TestService_initialRegistration tests device registration with posture collection
func TestService_initialRegistration(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("successful registration with healthy posture", func(t *testing.T) {
		// Create mock inventory server
		registrationRequests := 0
		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/devices" && r.Method == http.MethodPost {
				registrationRequests++

				var req registerRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid payload", http.StatusBadRequest)
					return
				}

				if req.ID != testDeviceID {
					t.Errorf("Expected device ID 'test-device', got %s", req.ID)
				}

				if req.PublicKey == "" {
					t.Error("Expected public key, got empty string")
				}

				if req.Posture == "" {
					t.Error("Expected posture data, got empty string")
				}

				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
					t.Fatalf("Failed to encode response: %v", err)
				}
			} else {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			}
		}))
		defer mockInventory.Close()

		// Create test config
		config := &Config{
			DeviceID:     testDeviceID,
			InventoryURL: mockInventory.URL,
			AttestURL:    "http://localhost:8443",
			KeyPath:      filepath.Join(tmpDir, "test.key"),
		}

		service := New(config)

		// Set mock posture collector
		service.collector = &mockPostureCollector{
			postureData: &posture.DevicePosture{
				Status:     "healthy",
				TrustScore: 85,
			},
		}

		// Generate a test private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		service.privateKey = privateKey

		// Test registration
		err = service.initialRegistration()
		if err != nil {
			t.Errorf("Registration failed: %v", err)
		}

		if registrationRequests != 1 {
			t.Errorf("Expected 1 registration request, got %d", registrationRequests)
		}
	})

	t.Run("handles posture collection failure", func(t *testing.T) {
		config := &Config{
			DeviceID:     testDeviceID,
			InventoryURL: "http://localhost:8081",
			KeyPath:      filepath.Join(tmpDir, "test.key"),
		}

		service := New(config)

		// Set mock posture collector that fails
		service.collector = &mockPostureCollector{
			shouldError: true,
		}

		// Generate a test private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		service.privateKey = privateKey

		// Test registration - should fail due to posture collection error
		err = service.initialRegistration()
		if err == nil {
			t.Error("Expected error due to posture collection failure")
		}

		if !strings.Contains(err.Error(), "collect posture") {
			t.Errorf("Expected posture collection error, got: %v", err)
		}
	})

	t.Run("handles inventory service failure", func(t *testing.T) {
		// Create mock inventory server that returns error
		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer mockInventory.Close()

		config := &Config{
			DeviceID:     testDeviceID,
			InventoryURL: mockInventory.URL,
			KeyPath:      filepath.Join(tmpDir, "test.key"),
		}

		service := New(config)

		// Set mock posture collector
		service.collector = &mockPostureCollector{
			postureData: &posture.DevicePosture{
				Status:     "healthy",
				TrustScore: 85,
			},
		}

		// Generate a test private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		service.privateKey = privateKey

		// Test registration - should fail due to inventory error
		err = service.initialRegistration()
		if err == nil {
			t.Error("Expected error due to inventory service failure")
		}
	})
}

// TestService_updatePosture tests posture updates
func TestService_updatePosture(t *testing.T) {
	t.Run("successful posture update", func(t *testing.T) {
		updateRequests := 0
		mockInventory := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/posture") && r.Method == http.MethodPost {
				updateRequests++

				var req updatePostureRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid payload", http.StatusBadRequest)
					return
				}

				if req.ID != testDeviceID {
					t.Errorf("Expected device ID %q, got %s", testDeviceID, req.ID)
				}

				if req.Posture == "" {
					t.Error("Expected posture data, got empty string")
				}

				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(map[string]string{"status": "updated"}); err != nil {
					t.Fatalf("Failed to encode response: %v", err)
				}
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		}))
		defer mockInventory.Close()

		config := &Config{
			DeviceID:     testDeviceID,
			InventoryURL: mockInventory.URL,
		}

		service := New(config)

		// Set mock posture collector
		service.collector = &mockPostureCollector{
			postureData: &posture.DevicePosture{
				Status:     "warning",
				TrustScore: 65,
			},
		}

		// Test posture update
		err := service.updatePosture()
		if err != nil {
			t.Errorf("Posture update failed: %v", err)
		}

		if updateRequests != 1 {
			t.Errorf("Expected 1 update request, got %d", updateRequests)
		}
	})

	t.Run("handles posture collection failure", func(t *testing.T) {
		config := &Config{
			DeviceID:     testDeviceID,
			InventoryURL: "http://localhost:8081",
		}

		service := New(config)

		// Set mock posture collector that fails
		service.collector = &mockPostureCollector{
			shouldError: true,
		}

		// Test posture update - should fail
		err := service.updatePosture()
		if err == nil {
			t.Error("Expected error due to posture collection failure")
		}
	})
}

// TestService_obtainCertificate tests certificate requests
func TestService_obtainCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("successful certificate request", func(t *testing.T) {
		certRequests := 0
		mockAuthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/certs/device" && r.Method == http.MethodPost {
				certRequests++

				var req map[string]string
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid payload", http.StatusBadRequest)
					return
				}

				if req["device_id"] != testDeviceID {
					t.Errorf("Expected device ID 'test-device', got %s", req["device_id"])
				}

				if req["csr"] == "" {
					t.Error("Expected CSR, got empty string")
				}

				// Return mock certificate
				response := certResponse{
					Certificate: "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----",
				}
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Fatalf("Failed to encode certificate response: %v", err)
				}
			} else if r.URL.Path == "/v1/certs/ca" && r.Method == http.MethodGet {
				// Return mock CA certificate
				w.Header().Set("Content-Type", "application/x-pem-file")
				if _, err := w.Write([]byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_DATA\n-----END CERTIFICATE-----")); err != nil {
					t.Fatalf("Failed to write CA certificate: %v", err)
				}
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		}))
		defer mockAuthz.Close()

		config := &Config{
			DeviceID:  testDeviceID,
			AttestURL: mockAuthz.URL,
			CertPath:  filepath.Join(tmpDir, "device.crt"),
			CAPath:    filepath.Join(tmpDir, "ca.pem"),
		}

		service := New(config)

		// Generate a test private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		service.privateKey = privateKey

		// Test certificate request
		err = service.obtainCertificate()
		if err != nil {
			t.Errorf("Certificate request failed: %v", err)
		}

		if certRequests != 1 {
			t.Errorf("Expected 1 certificate request, got %d", certRequests)
		}

		// Verify certificate was written
		if _, err := os.Stat(config.CertPath); err != nil {
			t.Fatalf("Certificate file verification failed: %v", err)
		}

		// Verify CA was downloaded and written
		if _, err := os.Stat(config.CAPath); err != nil {
			t.Fatalf("CA file verification failed: %v", err)
		}
	})

	t.Run("handles certificate request failure", func(t *testing.T) {
		mockAuthz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer mockAuthz.Close()

		config := &Config{
			DeviceID:  testDeviceID,
			AttestURL: mockAuthz.URL,
			CertPath:  filepath.Join(tmpDir, "device.crt"),
			CAPath:    filepath.Join(tmpDir, "ca.pem"),
		}

		service := New(config)

		// Generate a test private key
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}
		service.privateKey = privateKey

		// Test certificate request - should fail
		err = service.obtainCertificate()
		if err == nil {
			t.Error("Expected error due to certificate request failure")
		}
	})
}

// TestService_writePIDFile tests PID file creation
func TestService_writePIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	config := &Config{
		PIDFile: pidFile,
	}

	service := New(config)

	err := service.writePIDFile()
	if err != nil {
		t.Errorf("Failed to write PID file: %v", err)
	}

	// Verify PID file was created
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Error("PID file was not created")
	}

	// Verify PID file contains current process ID
	content, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("Failed to read PID file: %v", err)
	}

	if len(content) == initialCapacity {
		t.Error("PID file is empty")
	}
}

// TestService_removePIDFile tests PID file cleanup
func TestService_removePIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "test.pid")

	// Create PID file
	err := os.WriteFile(pidFile, []byte("12345\n"), pidFileMode)
	if err != nil {
		t.Fatalf("Failed to create test PID file: %v", err)
	}

	config := &Config{
		PIDFile: pidFile,
	}

	service := New(config)
	service.removePIDFile()

	// Verify PID file was removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file was not removed")
	}
}
