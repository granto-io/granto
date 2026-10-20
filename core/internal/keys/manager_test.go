package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/granto-io/granto/core/internal/config"
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
