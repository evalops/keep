package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultKeyPerm       = 0o600
	defaultCertPerm      = 0o600
	dirPermissions       = 0o700
	dirPermissionsSecure = 0o750
)

// GenerateSigningKey creates a new P256 ECDSA key and writes it to the provided path in PEM (PKCS8) format.
func GenerateSigningKey(path string) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(absPath), dirPermissions); err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	root, fileName, err := openFileRoot(absPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	file, err := root.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, defaultKeyPerm)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}

	return priv, nil
}

// LoadSigningKey reads an ECDSA private key from disk (PKCS8 PEM).
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	root, fileName, err := openFileRoot(absPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	file, err := root.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ECDSA private key in %s", path)
	}
	return priv, nil
}

// PublicKeyPEM converts the public portion of the key to PEM encoded SubjectPublicKeyInfo bytes.
func PublicKeyPEM(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// CreateCSR generates a PEM encoded certificate signing request using the provided key and device identifier.
func CreateCSR(priv *ecdsa.PrivateKey, deviceID string) ([]byte, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device id required")
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"keep-device"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// WriteCertificate writes PEM certificate data to disk with secure permissions.
func WriteCertificate(path string, pemData []byte) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(absPath), dirPermissionsSecure); err != nil {
		return err
	}

	root, fileName, err := openFileRoot(absPath)
	if err != nil {
		return err
	}
	defer root.Close()

	file, err := root.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, defaultCertPerm)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(pemData)
	return err
}

func openFileRoot(fullPath string) (*os.Root, string, error) {
	dir := filepath.Dir(fullPath)
	name := filepath.Base(fullPath)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", err
	}

	return root, name, nil
}

// CertificateExpiry parses PEM certificate data and returns the NotAfter timestamp.
func CertificateExpiry(pemData []byte) (time.Time, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}
