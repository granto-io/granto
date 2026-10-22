package oauth2_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestPKCEEmptyMethodIsPlain(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	rawCode := "code-plain-pkce"
	verifier := "plain-verifier-value"
	if err := d.codes.Create(ctx, &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(rawCode),
		TenantID:            domain.DefaultTenantID,
		ClientID:            "app-a",
		Subject:             "user-1",
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       verifier, // plain: challenge == verifier
		CodeChallengeMethod: "",       // omitted → plain per RFC 7636 §4.3
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tok, err := d.flow.ExchangeCode(ctx, oauth2.ExchangeCodeInput{
		ClientID:     "app-a",
		Code:         rawCode,
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("ExchangeCode plain default: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected access token")
	}
}

func TestPKCEEmptyMethodDoesNotTreatAsS256(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	rawCode := "code-s256-no-method"
	s256Verifier := "s256-verifier-abcdefghijklmnopqrstuvwxyz0123"
	sum := sha256.Sum256([]byte(s256Verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := d.codes.Create(ctx, &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(rawCode),
		TenantID:            domain.DefaultTenantID,
		ClientID:            "app-a",
		Subject:             "user-1",
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := d.flow.ExchangeCode(ctx, oauth2.ExchangeCodeInput{
		ClientID:     "app-a",
		Code:         rawCode,
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: s256Verifier,
	})
	if !errors.Is(err, oauth2.ErrInvalidCodeVerifier) {
		t.Fatalf("S256 challenge + empty method: err=%v, want invalid code_verifier", err)
	}
}

func TestPKCES256StillWorksWhenMethodSet(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	rawCode := "code-s256-explicit"
	verifier := "s256-verifier-abcdefghijklmnopqrstuvwxyz0123"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := d.codes.Create(ctx, &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(rawCode),
		TenantID:            domain.DefaultTenantID,
		ClientID:            "app-a",
		Subject:             "user-1",
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tok, err := d.flow.ExchangeCode(ctx, oauth2.ExchangeCodeInput{
		ClientID:     "app-a",
		Code:         rawCode,
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("ExchangeCode S256: %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("expected access token")
	}
}
