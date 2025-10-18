package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CertificateAuthority struct {
	cert       *x509.Certificate
	key        *ecdsa.PrivateKey
	certPath   string
	keyPath    string
	serialLock sync.Mutex
}

func LoadOrCreateCA(certPath, keyPath, commonName string, validFor time.Duration) (*CertificateAuthority, error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}

	if _, err := os.Stat(certPath); err == nil {
		return loadCA(certPath, keyPath)
	}

	if validFor == 0 {
		validFor = 10 * 365 * 24 * time.Hour
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"keep"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
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

	certOut, err := os.Create(certPath)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	defer keyOut.Close()
	encoded, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}); err != nil {
		return nil, err
	}

	return loadCA(certPath, keyPath)
}

func loadCA(certPath, keyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("failed to parse CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to parse CA key PEM")
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected CA private key type")
	}

	return &CertificateAuthority{cert: cert, key: priv, certPath: certPath, keyPath: keyPath}, nil
}

func (c *CertificateAuthority) IssueCertificate(subject pkix.Name, uris []string, dnsNames []string, ttl time.Duration, publicKey any) ([]byte, error) {
	if ttl == 0 {
		ttl = 8 * time.Hour
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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

	if len(dnsNames) > 0 {
		tpl.DNSNames = dnsNames
	}

	if len(uris) > 0 {
		parsed := make([]*url.URL, 0, len(uris))
		for _, raw := range uris {
			u, err := url.Parse(raw)
			if err != nil {
				return nil, err
			}
			parsed = append(parsed, u)
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
	if ttl == 0 {
		ttl = 8 * time.Hour
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
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
