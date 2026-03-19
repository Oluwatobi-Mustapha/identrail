package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCTokenVerifier validates OIDC bearer tokens using issuer discovery and JWKS verification.
type OIDCTokenVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewOIDCTokenVerifier constructs a verifier from issuer URL and expected audience.
func NewOIDCTokenVerifier(ctx context.Context, issuerURL string, audience string) (*OIDCTokenVerifier, error) {
	issuer := strings.TrimSpace(issuerURL)
	if issuer == "" {
		return nil, fmt.Errorf("oidc issuer url is required")
	}
	clientID := strings.TrimSpace(audience)
	if clientID == "" {
		return nil, fmt.Errorf("oidc audience is required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover oidc provider: %w", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	return &OIDCTokenVerifier{verifier: verifier}, nil
}

// VerifyToken verifies one raw bearer token and extracts normalized claims.
func (v *OIDCTokenVerifier) VerifyToken(ctx context.Context, rawToken string) (VerifiedToken, error) {
	idToken, err := v.verifier.Verify(ctx, strings.TrimSpace(rawToken))
	if err != nil {
		return VerifiedToken{}, err
	}

	var claims struct {
		Subject string   `json:"sub"`
		Scope   string   `json:"scope"`
		SCP     []string `json:"scp"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return VerifiedToken{}, fmt.Errorf("decode oidc claims: %w", err)
	}

	scopes := []string{}
	if scopeClaim := strings.TrimSpace(claims.Scope); scopeClaim != "" {
		scopes = append(scopes, strings.Fields(scopeClaim)...)
	}
	scopes = append(scopes, claims.SCP...)

	return VerifiedToken{
		Subject: strings.TrimSpace(claims.Subject),
		Scopes:  scopes,
	}, nil
}
