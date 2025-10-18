package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2/google"
)

var (
	issuerURL    = "https://accounts.google.com"
	googleJWKS   *oidc.KeySet
	googleVerifier *oidc.IDTokenVerifier
)

func initVerifier(audience string) (*oidc.IDTokenVerifier, error) {
	if audience == "" {
		return nil, errors.New("audience required")
	}
	providerCtx := context.Background()
	provider, err := oidc.NewProvider(providerCtx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("create provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: audience})
	return verifier, nil
}

func VerifyGoogleJWT(ctx context.Context, rawToken, audience string) (map[string]any, error) {
	if googleVerifier == nil {
		verifier, err := initVerifier(audience)
		if err != nil {
			return nil, err
		}
		googleVerifier = verifier
	}
	idToken, err := googleVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func FetchGoogleCertificates(ctx context.Context) (*google.Certificates, error) {
	certs, err := google.FetchCertificates(ctx)
	if err != nil {
		return nil, err
	}
	return &certs, nil
}

func CacheDuration() time.Duration {
	return time.Hour
}
