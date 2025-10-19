package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateSigningKey(t *testing.T) {
    tmpDir := t.TempDir()
    keyPath := filepath.Join(tmpDir, testKeyName)

	t.Run("generates valid ECDSA key", func(t *testing.T) {
		priv, err := GenerateSigningKey(keyPath)
		if err != nil {
			t.Fatalf("GenerateSigningKey failed: %v", err)
		}

		// Verify the key is ECDSA P256
		if priv.Curve != elliptic.P256() {
			t.Errorf("Expected P256 curve, got %v", priv.Curve.Params().Name)
		}

		// Verify file exists and has correct permissions
		fileInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Key file not created: %v", err)
		}

		if fileInfo.Mode().Perm() != 0o600 {
			t.Errorf("Expected file permissions 0600, got %v", fileInfo.Mode().Perm())
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		nestedPath := filepath.Join(tmpDir, "nested", "deep", "key.pem")

		_, err := GenerateSigningKey(nestedPath)
		if err != nil {
			t.Fatalf("GenerateSigningKey failed: %v", err)
		}

		if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
			t.Error("Key file was not created in nested directory")
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		existingPath := filepath.Join(tmpDir, "existing.key")

		// Create first key
		priv1, err := GenerateSigningKey(existingPath)
		if err != nil {
			t.Fatalf("First GenerateSigningKey failed: %v", err)
		}

		// Create second key (should overwrite)
		priv2, err := GenerateSigningKey(existingPath)
		if err != nil {
			t.Fatalf("Second GenerateSigningKey failed: %v", err)
		}

		// Keys should be different
		if priv1.D.Cmp(priv2.D) == 0 {
			t.Error("Expected different keys, but got the same key")
		}
	})

	t.Run("saves key in PKCS8 PEM format", func(t *testing.T) {
		keyPath := filepath.Join(tmpDir, "pkcs8.key")

		_, err := GenerateSigningKey(keyPath)
		if err != nil {
			t.Fatalf("GenerateSigningKey failed: %v", err)
		}

		// Read and verify the PEM format
		data, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("Failed to read key file: %v", err)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("Failed to decode PEM block")
		}

		if block.Type != "PRIVATE KEY" {
			t.Errorf("Expected PEM type 'PRIVATE KEY', got %s", block.Type)
		}

		// Verify it can be parsed as PKCS8
		_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Errorf("Failed to parse PKCS8 private key: %v", err)
		}
	})
}

func TestLoadSigningKey(t *testing.T) {
	tmpDir := t.TempDir()
    keyPath := filepath.Join(tmpDir, testKeyName)

	t.Run("loads valid key", func(t *testing.T) {
		// Generate a key first
		originalKey, err := GenerateSigningKey(keyPath)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Load the key
		loadedKey, err := LoadSigningKey(keyPath)
		if err != nil {
			t.Fatalf("LoadSigningKey failed: %v", err)
		}

		// Verify they're the same key
		if originalKey.D.Cmp(loadedKey.D) != 0 {
			t.Error("Loaded key does not match original key")
		}

		if !originalKey.PublicKey.Equal(&loadedKey.PublicKey) {
			t.Error("Public keys do not match")
		}
	})

	t.Run("fails with non-existent file", func(t *testing.T) {
		nonExistentPath := filepath.Join(tmpDir, "nonexistent.key")

		_, err := LoadSigningKey(nonExistentPath)
		if err == nil {
			t.Error("Expected error with non-existent file")
		}

		if !os.IsNotExist(err) {
			t.Errorf("Expected file not found error, got: %v", err)
		}
	})

	t.Run("fails with invalid PEM", func(t *testing.T) {
		invalidPEMPath := filepath.Join(tmpDir, "invalid.key")
		if err := os.WriteFile(invalidPEMPath, []byte("not a pem file"), 0o600); err != nil {
			t.Fatalf("Failed to write invalid PEM file: %v", err)
		}

		_, err := LoadSigningKey(invalidPEMPath)
		if err == nil {
			t.Error("Expected error with invalid PEM")
		}

		if !strings.Contains(err.Error(), "invalid PEM") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("fails with non-ECDSA key", func(t *testing.T) {
		// Create a file with an RSA key PEM structure
		rsaKeyPath := filepath.Join(tmpDir, "rsa.key")

		// This is a simplified test using invalid key data to test the type checking
		keyData := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB
wHVKYdZyLkmMdVNjJqLs2Nx7e62VQqTrqTqhqY+HVhMV7HjfRqNVM6pYsf3VrGQh
-----END PRIVATE KEY-----`)

		if err := os.WriteFile(rsaKeyPath, keyData, 0o600); err != nil {
			t.Fatalf("Failed to write RSA key: %v", err)
		}

		_, err := LoadSigningKey(rsaKeyPath)
		if err == nil {
			t.Error("Expected error with non-ECDSA key")
		}
	})

	t.Run("fails with corrupted key data", func(t *testing.T) {
		corruptPath := filepath.Join(tmpDir, "corrupt.key")

		// Write a PEM block with invalid key data
		corruptPEM := `-----BEGIN PRIVATE KEY-----
invalidbase64data!!!
-----END PRIVATE KEY-----`

		if err := os.WriteFile(corruptPath, []byte(corruptPEM), 0o600); err != nil {
			t.Fatalf("Failed to write corrupt PEM: %v", err)
		}

		_, err := LoadSigningKey(corruptPath)
		if err == nil {
			t.Error("Expected error with corrupted key data")
		}
	})
}

func TestPublicKeyPEM(t *testing.T) {
	tmpDir := t.TempDir()
    keyPath := filepath.Join(tmpDir, testKeyName)

	t.Run("converts to valid public key PEM", func(t *testing.T) {
        priv, err := GenerateSigningKey(keyPath)
        if err != nil {
            t.Fatalf(msgGenerateKeyFail, err)
        }

		pubPEM, err := PublicKeyPEM(priv)
		if err != nil {
			t.Fatalf("PublicKeyPEM failed: %v", err)
		}

		// Verify PEM format
		block, _ := pem.Decode(pubPEM)
		if block == nil {
			t.Fatal("Failed to decode public key PEM")
		}

		if block.Type != "PUBLIC KEY" {
			t.Errorf("Expected PEM type 'PUBLIC KEY', got %s", block.Type)
		}

		// Verify it can be parsed as a public key
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse public key: %v", err)
		}

		// Verify it's the same key
		ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Expected ECDSA public key")
		}

		if !priv.PublicKey.Equal(ecdsaPub) {
			t.Error("Public keys do not match")
		}
	})
}

func TestCreateCSR(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

    priv, err := GenerateSigningKey(keyPath)
    if err != nil {
        t.Fatalf(msgGenerateKeyFail, err)
    }

	t.Run("creates valid CSR", func(t *testing.T) {
		deviceID := "test-device-123"

		csrPEM, err := CreateCSR(priv, deviceID)
		if err != nil {
			t.Fatalf("CreateCSR failed: %v", err)
		}

		// Verify PEM format
		block, _ := pem.Decode(csrPEM)
		if block == nil {
			t.Fatal("Failed to decode CSR PEM")
		}

		if block.Type != "CERTIFICATE REQUEST" {
			t.Errorf("Expected PEM type 'CERTIFICATE REQUEST', got %s", block.Type)
		}

		// Parse and verify CSR
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		// Verify CSR properties
		if csr.Subject.CommonName != deviceID {
			t.Errorf("Expected CommonName %s, got %s", deviceID, csr.Subject.CommonName)
		}

		if len(csr.Subject.Organization) == 0 || csr.Subject.Organization[0] != "keep-device" {
			t.Errorf("Expected Organization 'keep-device', got %v", csr.Subject.Organization)
		}

		if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Errorf("Expected ECDSA-SHA256 signature algorithm, got %v", csr.SignatureAlgorithm)
		}

		// Verify signature
		if err := csr.CheckSignature(); err != nil {
			t.Errorf("CSR signature verification failed: %v", err)
		}

		// Verify public key matches
		csrPubKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("Expected ECDSA public key in CSR")
		}

		if !priv.PublicKey.Equal(csrPubKey) {
			t.Error("CSR public key does not match private key")
		}
	})

	t.Run("fails with empty device ID", func(t *testing.T) {
		_, err := CreateCSR(priv, "")
		if err == nil {
			t.Error("Expected error with empty device ID")
		}

		if !strings.Contains(err.Error(), "device id required") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("handles special characters in device ID", func(t *testing.T) {
		deviceID := "device-123_test.example.com"

		csrPEM, err := CreateCSR(priv, deviceID)
		if err != nil {
			t.Fatalf("CreateCSR failed with special characters: %v", err)
		}

		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		if csr.Subject.CommonName != deviceID {
			t.Errorf("Expected CommonName %s, got %s", deviceID, csr.Subject.CommonName)
		}
	})
}

func TestWriteCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("writes certificate to file", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "test.crt")
		certData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAMlyFqk69v+9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QtY2VydDAeFw0yM...")
-----END CERTIFICATE-----`)

		err := WriteCertificate(certPath, certData)
		if err != nil {
			t.Fatalf("WriteCertificate failed: %v", err)
		}

		// Verify file exists
		fileInfo, err := os.Stat(certPath)
		if err != nil {
			t.Fatalf("Certificate file not created: %v", err)
		}

		// Verify permissions
		if fileInfo.Mode().Perm() != 0o600 {
			t.Errorf("Expected file permissions 0600, got %v", fileInfo.Mode().Perm())
		}

		// Verify content
		writtenData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read certificate file: %v", err)
		}

		if string(writtenData) != string(certData) {
			t.Error("Written certificate data does not match input")
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		nestedPath := filepath.Join(tmpDir, "nested", "deep", "cert.pem")
		certData := []byte("test cert data")

		err := WriteCertificate(nestedPath, certData)
		if err != nil {
			t.Fatalf("WriteCertificate failed: %v", err)
		}

		if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
			t.Error("Certificate file was not created in nested directory")
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		certPath := filepath.Join(tmpDir, "overwrite.crt")

		// Write first certificate
		firstData := []byte("first certificate")
		err := WriteCertificate(certPath, firstData)
		if err != nil {
			t.Fatalf("First WriteCertificate failed: %v", err)
		}

		// Write second certificate
		secondData := []byte("second certificate")
		err = WriteCertificate(certPath, secondData)
		if err != nil {
			t.Fatalf("Second WriteCertificate failed: %v", err)
		}

		// Verify second data was written
		writtenData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read certificate file: %v", err)
		}

		if string(writtenData) != string(secondData) {
			t.Error("Certificate was not overwritten")
		}
	})
}

func TestCertificateExpiry(t *testing.T) {
	t.Run("parses expiry from valid certificate", func(t *testing.T) {
		// Create a test CA and certificate
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "ca.pem")
		keyPath := filepath.Join(tmpDir, "ca-key.pem")

		ca, err := LoadOrCreateCA(certPath, keyPath, "test-ca", 24*time.Hour)
		if err != nil {
			t.Fatalf("Failed to create CA: %v", err)
		}

		// Generate device key
		priv, err := GenerateSigningKey(filepath.Join(tmpDir, "device.key"))
		if err != nil {
			t.Fatalf("Failed to generate device key: %v", err)
		}

		// Issue a certificate with known TTL
		ttl := 2 * time.Hour
		subject := pkix.Name{CommonName: "test-device"}
		certPEM, err := ca.IssueCertificate(subject, nil, nil, ttl, &priv.PublicKey)
		if err != nil {
			t.Fatalf("Failed to issue certificate: %v", err)
		}

		// Test expiry parsing
		expiry, err := CertificateExpiry(certPEM)
		if err != nil {
			t.Fatalf("CertificateExpiry failed: %v", err)
		}

		// Verify the expiry is roughly what we expect
		expectedExpiry := time.Now().Add(ttl)
		timeDiff := expiry.Sub(expectedExpiry)
		if timeDiff < -time.Minute || timeDiff > time.Minute {
			t.Errorf("Certificate expiry %v is not close to expected %v", expiry, expectedExpiry)
		}
	})

	t.Run("fails with invalid PEM", func(t *testing.T) {
		invalidPEM := []byte("not a certificate")

		_, err := CertificateExpiry(invalidPEM)
		if err == nil {
			t.Error("Expected error with invalid PEM")
		}

		if !strings.Contains(err.Error(), "invalid certificate pem") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("fails with corrupted certificate", func(t *testing.T) {
		corruptCert := []byte(`-----BEGIN CERTIFICATE-----
invalid certificate data
-----END CERTIFICATE-----`)

		_, err := CertificateExpiry(corruptCert)
		if err == nil {
			t.Error("Expected error with corrupted certificate")
		}
	})
}

// Benchmark tests
func BenchmarkGenerateSigningKey(b *testing.B) {
    tmpDir := b.TempDir()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        keyPath := filepath.Join(tmpDir, benchKeyName)
        _, err := GenerateSigningKey(keyPath)
        if err != nil {
            b.Fatalf("GenerateSigningKey failed: %v", err)
        }
        os.Remove(keyPath) // Clean up
    }
}

func BenchmarkCreateCSR(b *testing.B) {
    tmpDir := b.TempDir()
        keyPath := filepath.Join(tmpDir, benchKeyName)

    priv, err := GenerateSigningKey(keyPath)
    if err != nil {
        b.Fatalf(msgGenerateKeyFail, err)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := CreateCSR(priv, "bench-device")
        if err != nil {
            b.Fatalf("CreateCSR failed: %v", err)
        }
    }
}

func BenchmarkPublicKeyPEM(b *testing.B) {
	tmpDir := b.TempDir()
    keyPath := filepath.Join(tmpDir, benchKeyName)

    priv, err := GenerateSigningKey(keyPath)
    if err != nil {
        b.Fatalf(msgGenerateKeyFail, err)
    }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := PublicKeyPEM(priv)
		if err != nil {
			b.Fatalf("PublicKeyPEM failed: %v", err)
		}
	}
}
