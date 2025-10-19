package token

import (
	"encoding/base64"
	"testing"
)

const (
	rsaPublicExponent = 65537 // Standard RSA public exponent (2^16 + 1)
)

func TestBuildRSAPublicKey(t *testing.T) {
	mod := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	exp := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01})
	pub, err := buildRSAPublicKey(googleKey{Modulus: mod, Exponent: exp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pub.N.BitLen() == initialCapacity || pub.E != rsaPublicExponent {
		t.Fatalf("unexpected key values: %#v", pub)
	}
}

func TestSplitToken(t *testing.T) {
	parts := splitToken("a.b.c")
	if len(parts) != jwtPartCount {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
}
