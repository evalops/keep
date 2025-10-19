package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOrCreateCA(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	const (
		testCAName    = "test-ca"
		testCADefault = "test-ca-default"
	)

	t.Run("creates new CA when files don't exist", func(t *testing.T) {
		ca, err := LoadOrCreateCA(certPath, keyPath, testCAName, time.Hour*24*365)
		if err != nil {
			t.Fatalf("LoadOrCreateCA failed: %v", err)
		}

		// Verify files exist
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Error("CA certificate file was not created")
		}
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Error("CA private key file was not created")
		}

		// Verify certificate properties
		if ca.cert.Subject.CommonName != testCAName {
			t.Errorf("Expected CommonName %q, got %s", testCAName, ca.cert.Subject.CommonName)
		}
		if !ca.cert.IsCA {
			t.Error("Certificate should be a CA")
		}
		if ca.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Error("CA should have CertSign usage")
		}
	})

	t.Run("loads existing CA when files exist", func(t *testing.T) {
		// Load the existing CA
		ca2, err := LoadOrCreateCA(certPath, keyPath, "different-name", time.Hour)
		if err != nil {
			t.Fatalf("LoadOrCreateCA failed: %v", err)
		}

		// Should load existing CA, not create new one with different name
		if ca2.cert.Subject.CommonName != testCAName {
			t.Errorf("Expected existing CommonName %q, got %s", testCAName, ca2.cert.Subject.CommonName)
		}
	})

	t.Run("uses default validity period when zero", func(t *testing.T) {
		tmpDir2 := t.TempDir()
		certPath2 := filepath.Join(tmpDir2, "ca.pem")
		keyPath2 := filepath.Join(tmpDir2, "ca-key.pem")

		ca, err := LoadOrCreateCA(certPath2, keyPath2, testCADefault, 0)
		if err != nil {
			t.Fatalf("LoadOrCreateCA failed: %v", err)
		}

		// Check that it uses the default 10 year validity
		validFor := ca.cert.NotAfter.Sub(ca.cert.NotBefore)
		expectedMinimum := 10*365*24*time.Hour - time.Hour // Allow some variance
		if validFor < expectedMinimum {
			t.Errorf("Default validity period too short: %v", validFor)
		}
	})
}

func TestLoadCA(t *testing.T) {
	t.Run("fails with invalid certificate PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")
		keyPath := filepath.Join(tmpDir, "key.pem")

		// Write invalid certificate
		if err := os.WriteFile(certPath, []byte("invalid pem"), 0o600); err != nil {
			t.Fatalf("failed to write invalid certificate: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----"), 0o600); err != nil {
			t.Fatalf("failed to write invalid key: %v", err)
		}

		_, err := LoadCA(certPath, keyPath)
		if err == nil {
			t.Error("Expected error with invalid certificate PEM")
		}
		if !strings.Contains(err.Error(), "failed to parse CA certificate PEM") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("fails with invalid key PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")
		keyPath := filepath.Join(tmpDir, "invalid-key.pem")

		// Create a valid certificate first
		_, err := LoadOrCreateCA(certPath, keyPath, "test", time.Hour)
		if err != nil {
			t.Fatalf("Failed to create initial CA: %v", err)
		}

		// Now corrupt the key file
		if err := os.WriteFile(keyPath, []byte("invalid key pem"), 0o600); err != nil {
			t.Fatalf("failed to corrupt key file: %v", err)
		}

		_, err = LoadCA(certPath, keyPath)
		if err == nil {
			t.Error("Expected error with invalid key PEM")
		}
		if !strings.Contains(err.Error(), "failed to parse CA key PEM") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})

	t.Run("fails when key file doesn't exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")
		keyPath := filepath.Join(tmpDir, "nonexistent-key.pem")

		// Create only certificate
		_, err := LoadOrCreateCA(certPath, keyPath, "test", time.Hour)
		if err != nil {
			t.Fatalf("Failed to create initial CA: %v", err)
		}

		// Remove key file
		if err := os.Remove(keyPath); err != nil {
			t.Fatalf("failed to remove key file: %v", err)
		}

		_, err = LoadCA(certPath, keyPath)
		if err == nil {
			t.Error("Expected error when key file doesn't exist")
		}
	})
}

func TestCertificateAuthority_IssueCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	ca, err := LoadOrCreateCA(certPath, keyPath, testCAName, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate a key for the certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("issues valid certificate", func(t *testing.T) {
		subject := pkix.Name{
			CommonName:   "test-device",
			Organization: []string{"test-org"},
		}
		uris := []string{"spiffe://example.com/device/123"}
		dnsNames := []string{"device.example.com"}
		ttl := time.Hour

		certPEM, err := ca.IssueCertificate(subject, uris, dnsNames, ttl, &priv.PublicKey)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		// Parse and verify the certificate
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("Failed to decode certificate PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Verify certificate properties
		if cert.Subject.CommonName != "test-device" {
			t.Errorf("Expected CommonName 'test-device', got %s", cert.Subject.CommonName)
		}
		if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "test-org" {
			t.Errorf("Expected Organization 'test-org', got %v", cert.Subject.Organization)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device.example.com" {
			t.Errorf("Expected DNSNames [device.example.com], got %v", cert.DNSNames)
		}
		if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.com/device/123" {
			t.Errorf("Expected URIs [spiffe://example.com/device/123], got %v", cert.URIs)
		}

		// Verify the certificate is signed by the CA
		roots := x509.NewCertPool()
		roots.AddCert(ca.cert)
		opts := x509.VerifyOptions{Roots: roots}
		if _, err := cert.Verify(opts); err != nil {
			t.Errorf("Certificate verification failed: %v", err)
		}
	})

	t.Run("uses default TTL when zero", func(t *testing.T) {
		subject := pkix.Name{CommonName: "test-device"}

		certPEM, err := ca.IssueCertificate(subject, nil, nil, 0, &priv.PublicKey)
		if err != nil {
			t.Fatalf("IssueCertificate failed: %v", err)
		}

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Should use default 8 hour TTL
		duration := cert.NotAfter.Sub(cert.NotBefore)
		if duration < 7*time.Hour || duration > 9*time.Hour {
			t.Errorf("Expected ~8 hour TTL, got %v", duration)
		}
	})

	t.Run("handles invalid URI", func(t *testing.T) {
		subject := pkix.Name{CommonName: "test-device"}
		invalidURIs := []string{"not://a valid uri with spaces"}

		_, err := ca.IssueCertificate(subject, invalidURIs, nil, time.Hour, &priv.PublicKey)
		if err == nil {
			t.Error("Expected error with invalid URI")
		}
	})
}

func TestCertificateAuthority_SignCSR(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	ca, err := LoadOrCreateCA(certPath, keyPath, testCAName, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Generate a key and CSR
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("signs valid CSR", func(t *testing.T) {
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "device-123",
				Organization: []string{"keep-device"},
			},
			DNSNames:           []string{"device-123.local"},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		certPEM, err := ca.SignCSR(csr, time.Hour)
		if err != nil {
			t.Fatalf("SignCSR failed: %v", err)
		}

		// Parse and verify the certificate
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Verify certificate properties match CSR
		if cert.Subject.CommonName != "device-123" {
			t.Errorf("Expected CommonName 'device-123', got %s", cert.Subject.CommonName)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "device-123.local" {
			t.Errorf("Expected DNSNames [device-123.local], got %v", cert.DNSNames)
		}

		// Verify the certificate is signed by the CA
		roots := x509.NewCertPool()
		roots.AddCert(ca.cert)
		opts := x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			t.Errorf("Certificate verification failed: %v", err)
		}
	})

	t.Run("fails with invalid CSR signature", func(t *testing.T) {
		// Create a CSR with invalid signature
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "invalid"},
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		// Corrupt the signature
		csr.Signature = []byte("invalid signature")

		_, err = ca.SignCSR(csr, time.Hour)
		if err == nil {
			t.Error("Expected error with invalid CSR signature")
		}
	})

	t.Run("uses default TTL when zero", func(t *testing.T) {
		csrTemplate := &x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: "device-default-ttl"},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
		if err != nil {
			t.Fatalf("Failed to create CSR: %v", err)
		}

		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("Failed to parse CSR: %v", err)
		}

		certPEM, err := ca.SignCSR(csr, 0) // Use default TTL
		if err != nil {
			t.Fatalf("SignCSR failed: %v", err)
		}

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		// Should use default 8 hour TTL
		duration := cert.NotAfter.Sub(cert.NotBefore)
		if duration < 7*time.Hour || duration > 9*time.Hour {
			t.Errorf("Expected ~8 hour TTL, got %v", duration)
		}
	})
}

func TestCertificateAuthority_CertificatePEM(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	ca, err := LoadOrCreateCA(certPath, keyPath, testCAName, time.Hour*24)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	t.Run("returns valid PEM data", func(t *testing.T) {
		pemData, err := ca.CertificatePEM()
		if err != nil {
			t.Fatalf("CertificatePEM failed: %v", err)
		}

		// Verify it's valid PEM
		block, _ := pem.Decode(pemData)
		if block == nil {
			t.Error("Failed to decode PEM data")
		}

		if block.Type != "CERTIFICATE" {
			t.Errorf("Expected PEM type 'CERTIFICATE', got %s", block.Type)
		}

		// Verify it parses as a certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("Failed to parse certificate from PEM: %v", err)
		}

		if cert.Subject.CommonName != testCAName {
			t.Errorf("Expected CommonName %q, got %s", testCAName, cert.Subject.CommonName)
		}
	})
}

// Benchmark tests
func BenchmarkLoadOrCreateCA(b *testing.B) {
	tmpDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		certPath := filepath.Join(tmpDir, "bench-ca.pem")
		keyPath := filepath.Join(tmpDir, "bench-ca-key.pem")

		_, err := LoadOrCreateCA(certPath, keyPath, "bench-ca", time.Hour*24)
		if err != nil {
			b.Fatalf("LoadOrCreateCA failed: %v", err)
		}

		// Clean up for next iteration (except last)
		if i < b.N-1 {
			os.Remove(certPath)
			os.Remove(keyPath)
		}
	}
}

func BenchmarkIssueCertificate(b *testing.B) {
	tmpDir := b.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	ca, err := LoadOrCreateCA(certPath, keyPath, "bench-ca", time.Hour*24)
	if err != nil {
		b.Fatalf("Failed to create CA: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	subject := pkix.Name{CommonName: "bench-device"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ca.IssueCertificate(subject, nil, nil, time.Hour, &priv.PublicKey)
		if err != nil {
			b.Fatalf("IssueCertificate failed: %v", err)
		}
	}
}
