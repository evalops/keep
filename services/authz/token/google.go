package token

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type googleKey struct {
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

type googleJWKS struct {
	Keys []googleKey `json:"keys"`
}

type cacheEntry struct {
	publicKey *rsa.PublicKey
	expires   time.Time
}

var (
	cacheMu    sync.Mutex
	keyCache   = map[string]cacheEntry{}
	httpClient = &http.Client{Timeout: 5 * time.Second}
)

func VerifyGoogleJWT(ctx context.Context, rawToken, audience string) (map[string]any, error) {
	if audience == "" {
		return nil, errors.New("audience required")
	}
	parts := splitToken(rawToken)
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt format")
	}

	headers, err := decodeSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	claimsJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	var header struct {
		KeyID string `json:"kid"`
		Alg   string `json:"alg"`
	}
	if err := json.Unmarshal(headers, &header); err != nil {
		return nil, err
	}

	if header.Alg != "RS256" {
		return nil, errors.New("unsupported algorithm")
	}

	pubKey, err := fetchGooglePublicKey(ctx, header.KeyID)
	if err != nil {
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	signed := []byte(parts[0] + "." + parts[1])
	h := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], sig); err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	if aud, ok := claims["aud"].(string); !ok || aud != audience {
		return nil, errors.New("audience mismatch")
	}

	if iss, ok := claims["iss"].(string); !ok || iss != "https://accounts.google.com" {
		return nil, errors.New("issuer mismatch")
	}

	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); !ok || int64(exp) < now {
		return nil, errors.New("token expired")
	}

	if iat, ok := claims["iat"].(float64); !ok || int64(iat) > now+60 {
		return nil, errors.New("invalid issued time")
	}

	return claims, nil
}

func fetchGooglePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	cacheMu.Lock()
	entry, ok := keyCache[kid]
	if ok && entry.expires.After(time.Now()) {
		cacheMu.Unlock()
		return entry.publicKey, nil
	}
	cacheMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/certs", nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var jwks googleJWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	maxAge := extractMaxAge(resp.Header.Get("Cache-Control"))
	expires := time.Now().Add(maxAge)

	cacheMu.Lock()
	defer cacheMu.Unlock()

	for _, key := range jwks.Keys {
		pubKey, err := buildRSAPublicKey(key)
		if err != nil {
			continue
		}
		keyCache[key.KeyID] = cacheEntry{publicKey: pubKey, expires: expires}
		if key.KeyID == kid {
			return pubKey, nil
		}
	}

	if entry, ok := keyCache[kid]; ok {
		return entry.publicKey, nil
	}

	return nil, errors.New("key not found")
}

func buildRSAPublicKey(k googleKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.Modulus)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.Exponent)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func splitToken(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

func extractMaxAge(cacheControl string) time.Duration {
	if cacheControl == "" {
		return time.Hour
	}
	for _, part := range strings.Split(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			secs, err := strconv.Atoi(strings.TrimPrefix(part, "max-age="))
			if err == nil {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return time.Hour
}
