package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestUserInfoRequiresOpenIDAccessToken(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	raw := "userinfo-access-token"
	at := &domain.AccessToken{
		TokenHash: domain.HashToken(raw),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		Scopes:    []string{"openid", "profile"},
		Extra: map[string]any{
			"id_token": map[string]any{
				"email": "user@example.com",
				"name":  "User One",
			},
		},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := d.tokens.CreateAccessToken(ctx, at); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	claims, err := d.flow.UserInfo(ctx, raw)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("sub = %v, want user-1", claims["sub"])
	}
	if claims["email"] != "user@example.com" || claims["name"] != "User One" {
		t.Fatalf("claims = %#v, want email/name from Extra.id_token", claims)
	}

	_, err = d.flow.UserInfo(ctx, "missing-token")
	if !errors.Is(err, oauth2.ErrInvalidToken) {
		t.Fatalf("missing token: err=%v, want invalid_token", err)
	}

	rawNoOpenID := "no-openid-token"
	if err := d.tokens.CreateAccessToken(ctx, &domain.AccessToken{
		TokenHash: domain.HashToken(rawNoOpenID),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		Scopes:    []string{"profile"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateAccessToken no openid: %v", err)
	}
	_, err = d.flow.UserInfo(ctx, rawNoOpenID)
	if !errors.Is(err, oauth2.ErrInsufficientScope) {
		t.Fatalf("no openid: err=%v, want insufficient_scope", err)
	}
}
