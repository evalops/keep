package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCAValidity                   = 10 * 365 * 24 * time.Hour
	defaultCertificateTTL               = 8 * time.Hour
	defaultClockSkew                    = 5 * time.Minute
	permOwnerReadWrite                  = 0o600
	permOwnerReadExecute                = 0o750
	permOwnerReadGroup                  = 0o640
	maxSerialShift                      = 128
	initialCapacity                     = 0
	bigIntOne                           = 1
	zeroDuration          time.Duration = 0

	// Error messages
	errParseCACert       = "failed to parse CA certificate PEM"
	errParseCAKey        = "failed to parse CA key PEM"
	errUnexpectedKeyType = "unexpected CA private key type"
)

// validatePath ensures the path is safe from directory traversal attacks
func validatePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path is empty")
	}

	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path contains directory traversal: %s", path)
	}

	return nil
}

type CertificateAuthority struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	certPath string
	keyPath  string
}

// LoadOrCreateCA loads an existing CA or creates a new one if files don't exist
func LoadOrCreateCA(certPath, keyPath, commonName string, validFor time.Duration) (*CertificateAuthority, error) {
	if err := validatePath(certPath); err != nil {
		return nil, fmt.Errorf("invalid certificate path: %w", err)
	}
	if err := validatePath(keyPath); err != nil {
		return nil, fmt.Errorf("invalid key path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), permOwnerReadExecute); err != nil {
		return nil, fmt.Errorf("failed to create certificate directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), permOwnerReadExecute); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	if _, err := os.Stat(certPath); err == nil {
		return LoadCA(certPath, keyPath)
	}

	if validFor == zeroDuration {
		validFor = defaultCAValidity
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(bigIntOne), maxSerialShift)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"keep"},
		},
		NotBefore:             time.Now().Add(-defaultClockSkew),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	if writeErr := writeFileSecure(certPath, permOwnerReadGroup, func(f *os.File) error {
		return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	}); writeErr != nil {
		return nil, writeErr
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if writeErr := writeFileSecure(keyPath, permOwnerReadWrite, func(f *os.File) error {
		return pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: encoded})
	}); writeErr != nil {
		return nil, writeErr
	}

	return LoadCA(certPath, keyPath)
}

// LoadCA loads an existing CA from certificate and key files
func LoadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	if err := validatePath(certPath); err != nil {
		return nil, fmt.Errorf("invalid cert path: %w", err)
	}
	if err := validatePath(keyPath); err != nil {
		return nil, fmt.Errorf("invalid key path: %w", err)
	}

	// Paths are validated above - G304 is false positive
	certPEM, err := os.ReadFile(certPath) // #nosec G304
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New(errParseCACert)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New(errParseCAKey)
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New(errUnexpectedKeyType)
	}

	return &CertificateAuthority{cert: cert, key: priv, certPath: certPath, keyPath: keyPath}, nil
}

func writeFileSecure(path string, perm os.FileMode, writeFn func(*os.File) error) error {
	if err := validatePath(path); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), permOwnerReadExecute); err != nil {
		return err
	}

	// Path is validated above - G304 is false positive
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm) // #nosec G304
	if err != nil {
		return err
	}
	defer file.Close()

	return writeFn(file)
}

func (c *CertificateAuthority) IssueCertificate(subject pkix.Name, uris []string, dnsNames []string, ttl time.Duration, publicKey any) ([]byte, error) {
	if ttl == zeroDuration {
		ttl = defaultCertificateTTL
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(bigIntOne), maxSerialShift))
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	if len(dnsNames) > initialCapacity {
		tpl.DNSNames = dnsNames
	}

	if len(uris) > initialCapacity {
		parsed := make([]*url.URL, initialCapacity, len(uris))
		for _, raw := range uris {
			parsedURL, parseErr := url.Parse(raw)
			if parseErr != nil {
				return nil, parseErr
			}
			parsed = append(parsed, parsedURL)
		}
		tpl.URIs = parsed
	}

	tpl.PublicKey = publicKey

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, publicKey, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func (c *CertificateAuthority) SignCSR(csr *x509.CertificateRequest, ttl time.Duration) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	if ttl == zeroDuration {
		ttl = defaultCertificateTTL
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(bigIntOne), maxSerialShift))
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber:       serial,
		Subject:            csr.Subject,
		DNSNames:           csr.DNSNames,
		URIs:               csr.URIs,
		IPAddresses:        csr.IPAddresses,
		EmailAddresses:     csr.EmailAddresses,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           time.Now().Add(ttl),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	tpl.PublicKey = csr.PublicKey

	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func (c *CertificateAuthority) CertificatePEM() ([]byte, error) {
	return os.ReadFile(c.certPath)
}
