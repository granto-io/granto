package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/keys"
	"github.com/granto-io/granto/core/internal/oidc"
)

func TestIssueIDTokenWithOpenID(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	cfg := &config.Config{
		Token: config.TokenConfig{
			Issuer:           "https://auth.example",
			DefaultAlgorithm: "RS256",
			IDTokenTTL:       time.Hour,
			SigningKeys: config.SigningKeysConfig{
				PrivateKeyPEM: string(pemBytes),
				KID:           "k1",
			},
		},
	}
	mgr, err := keys.NewManager(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	issuer := oidc.NewIDTokens(cfg, mgr)

	sid := uuid.New()
	raw, err := issuer.Issue(context.Background(), oidc.IssueInput{
		ClientID:  "app-a",
		Subject:   "user-1",
		SessionID: sid,
		AuthTime:  time.Unix(1_700_000_000, 0).UTC(),
		Nonce:     "n-1",
		Scopes:    []string{"openid", "profile"},
		Extra: map[string]any{
			"id_token": map[string]any{"email": "u@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if raw == "" {
		t.Fatal("expected id_token")
	}

	tok, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("parse: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-1" || claims["aud"] != "app-a" || claims["nonce"] != "n-1" {
		t.Fatalf("claims = %#v", claims)
	}
	if claims["email"] != "u@example.com" {
		t.Fatalf("email claim missing: %#v", claims)
	}

	empty, err := issuer.Issue(context.Background(), oidc.IssueInput{
		ClientID: "app-a",
		Subject:  "user-1",
		Scopes:   []string{"profile"},
	})
	if err != nil || empty != "" {
		t.Fatalf("without openid: token=%q err=%v", empty, err)
	}
}

func TestIssueLogoutToken(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	cfg := &config.Config{
		Token: config.TokenConfig{
			Issuer:           "https://auth.example",
			DefaultAlgorithm: "RS256",
			SigningKeys: config.SigningKeysConfig{
				PrivateKeyPEM: string(pemBytes),
				KID:           "k1",
			},
		},
	}
	mgr, err := keys.NewManager(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	issuer := oidc.NewIDTokens(cfg, mgr)
	sid := uuid.New()

	raw, err := issuer.IssueLogoutToken(context.Background(), "app-a", "user-1", sid)
	if err != nil {
		t.Fatalf("IssueLogoutToken: %v", err)
	}
	tok, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("parse: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-1" || claims["aud"] != "app-a" || claims["sid"] != sid.String() {
		t.Fatalf("claims = %#v", claims)
	}
	if claims["nonce"] != nil {
		t.Fatal("logout_token must not contain nonce")
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim missing: %#v", claims["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("backchannel-logout event missing: %#v", events)
	}
}
