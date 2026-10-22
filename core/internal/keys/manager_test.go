package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/keys"
)

func TestManagerStaticPEMSignAndJWKS(t *testing.T) {
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
				KID:           "test-kid",
			},
		},
	}

	mgr, err := keys.NewManager(context.Background(), cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	signed, err := mgr.SignJWT(jwt.MapClaims{"sub": "user-1", "iss": "https://auth.example"})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if signed == "" {
		t.Fatal("empty JWT")
	}

	jwks, err := mgr.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != "test-kid" || jwks.Keys[0].Kty != "RSA" {
		t.Fatalf("JWKS = %+v", jwks)
	}

	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("verify JWT: err=%v valid=%v", err, parsed != nil && parsed.Valid)
	}
}

type countingSigningKeyRepo struct {
	listCalls int
	active    *domain.SigningKey
	all       []*domain.SigningKey
}

func (r *countingSigningKeyRepo) GetActiveKey(_ context.Context, _ uuid.UUID, algorithm string) (*domain.SigningKey, error) {
	if r.active == nil || r.active.Algorithm != algorithm {
		return nil, domain.ErrSigningKeyNotFound
	}
	cp := *r.active
	return &cp, nil
}

func (r *countingSigningKeyRepo) ListActiveKeys(_ context.Context, _ uuid.UUID) ([]*domain.SigningKey, error) {
	r.listCalls++
	out := make([]*domain.SigningKey, 0, len(r.all))
	for _, k := range r.all {
		cp := *k
		out = append(out, &cp)
	}
	return out, nil
}

func (r *countingSigningKeyRepo) Create(_ context.Context, key *domain.SigningKey) error {
	cp := *key
	r.active = &cp
	r.all = append(r.all, &cp)
	return nil
}

func TestManagerJWKSCachesListActiveKeys(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	master := strings.Repeat("a", 32)
	enc, err := keys.NewAESEncryptor(master)
	if err != nil {
		t.Fatalf("NewAESEncryptor: %v", err)
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	ciphertext, err := enc.Encrypt(privPEM)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rec := &domain.SigningKey{
		ID:         uuid.New(),
		TenantID:   domain.DefaultTenantID,
		KID:        "cached-kid",
		Algorithm:  "RS256",
		Use:        "sig",
		PublicKey:  string(pubPEM),
		PrivateKey: base64.StdEncoding.EncodeToString(ciphertext),
		IsActive:   true,
	}
	repo := &countingSigningKeyRepo{active: rec, all: []*domain.SigningKey{rec}}
	cfg := &config.Config{
		Token: config.TokenConfig{
			Issuer:           "https://auth.example",
			DefaultAlgorithm: "RS256",
			MasterKey:        master,
		},
	}
	mgr, err := keys.NewManager(ctx, cfg, repo, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if _, err := mgr.JWKS(ctx); err != nil {
		t.Fatalf("JWKS #1: %v", err)
	}
	if _, err := mgr.JWKS(ctx); err != nil {
		t.Fatalf("JWKS #2: %v", err)
	}
	if repo.listCalls != 1 {
		t.Fatalf("ListActiveKeys calls = %d, want 1 (cached)", repo.listCalls)
	}
}
