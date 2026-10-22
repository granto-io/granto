package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestAuthenticateClientUnknownRunsComparableWork(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	secret := "probe-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte("real-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	d.clients.byID["conf-a"] = &domain.Client{
		ClientID:                "conf-a",
		TenantID:                domain.DefaultTenantID,
		ClientType:              domain.ClientTypeConfidential,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
		ClientSecretHash:        string(hash),
		GrantTypes:              []domain.GrantType{domain.GrantTypeClientCredentials},
	}

	// Warm dummy hash (GenerateFromPassword once) outside the timed paths.
	_, _ = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "warmup-unknown",
		ClientSecret: secret,
	})

	// Wrong secret on existing confidential client.
	start := time.Now()
	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "conf-a",
		ClientSecret: secret,
	})
	confidentialDur := time.Since(start)
	if !errors.Is(err, oauth2.ErrInvalidClientSecret) {
		t.Fatalf("confidential wrong secret: err=%v", err)
	}

	start = time.Now()
	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "no-such-client",
		ClientSecret: secret,
	})
	unknownDur := time.Since(start)
	if !errors.Is(err, oauth2.ErrInvalidClient) {
		t.Fatalf("unknown client: err=%v", err)
	}

	// Both paths must pay bcrypt.DefaultCost — unknown must not be ~instant.
	if unknownDur < confidentialDur/5 {
		t.Fatalf("unknown client too fast (%v) vs confidential wrong secret (%v); timing leak?", unknownDur, confidentialDur)
	}
}

func TestAuthenticateClientEmptySecretStillChecksHash(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	hash, err := bcrypt.GenerateFromPassword([]byte("real-secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	d.clients.byID["conf-b"] = &domain.Client{
		ClientID:                "conf-b",
		TenantID:                domain.DefaultTenantID,
		ClientType:              domain.ClientTypeConfidential,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
		ClientSecretHash:        string(hash),
		GrantTypes:              []domain.GrantType{domain.GrantTypeClientCredentials},
	}

	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "conf-b",
		ClientSecret: "",
	})
	if !errors.Is(err, oauth2.ErrInvalidClientSecret) {
		t.Fatalf("empty secret: err=%v, want invalid client secret", err)
	}
}
