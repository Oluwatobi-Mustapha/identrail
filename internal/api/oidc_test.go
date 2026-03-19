package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeRawTokenVerifier struct {
	token tokenClaimsDecoder
	err   error
}

func (f fakeRawTokenVerifier) Verify(context.Context, string) (tokenClaimsDecoder, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.token, nil
}

type fakeClaimsDecoder struct {
	claims map[string]any
	err    error
}

func (d fakeClaimsDecoder) Claims(v interface{}) error {
	if d.err != nil {
		return d.err
	}
	payload, err := json.Marshal(d.claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

func TestNewOIDCTokenVerifierValidation(t *testing.T) {
	if _, err := NewOIDCTokenVerifier(context.Background(), "", "aud"); err == nil {
		t.Fatal("expected missing issuer validation error")
	}
	if _, err := NewOIDCTokenVerifier(context.Background(), "https://issuer.example.com", ""); err == nil {
		t.Fatal("expected missing audience validation error")
	}
}

func TestNewOIDCTokenVerifierDiscoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if _, err := NewOIDCTokenVerifier(context.Background(), srv.URL, "identrail"); err == nil {
		t.Fatal("expected discovery failure")
	}
}

func TestOIDCTokenVerifierVerifyToken(t *testing.T) {
	verifier := &OIDCTokenVerifier{
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{
				claims: map[string]any{
					"sub":   "subject-1",
					"scope": "read write",
					"scp":   []string{"identrail.admin"},
				},
			},
		},
	}

	token, err := verifier.VerifyToken(context.Background(), "token")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if token.Subject != "subject-1" {
		t.Fatalf("unexpected subject %q", token.Subject)
	}
	if len(token.Scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %+v", token.Scopes)
	}
}

func TestOIDCTokenVerifierVerifyTokenErrors(t *testing.T) {
	if _, err := (&OIDCTokenVerifier{}).VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected nil verifier error")
	}

	verifierErr := &OIDCTokenVerifier{
		verifier: fakeRawTokenVerifier{err: errors.New("invalid token")},
	}
	if _, err := verifierErr.VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected verify error")
	}

	claimsErr := &OIDCTokenVerifier{
		verifier: fakeRawTokenVerifier{
			token: fakeClaimsDecoder{err: errors.New("bad claims")},
		},
	}
	if _, err := claimsErr.VerifyToken(context.Background(), "token"); err == nil {
		t.Fatal("expected claims decode error")
	}
}
