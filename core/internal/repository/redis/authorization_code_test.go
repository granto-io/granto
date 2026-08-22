package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	iredis "github.com/granto-io/granto/core/internal/redis"
	reporredis "github.com/granto-io/granto/core/internal/repository/redis"
)

func newAuthorizationCodeTestRepo(t *testing.T) *reporredis.AuthorizationCodeRepository {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	client, err := iredis.NewClient(context.Background(), config.RedisConfig{
		Addr:     mr.Addr(),
		PoolSize: 2,
	})
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return reporredis.NewAuthorizationCodeRepository(client)
}

func sampleAuthorizationCode(t *testing.T, raw string) *domain.AuthorizationCode {
	t.Helper()
	return &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(raw),
		TenantID:            domain.DefaultTenantID,
		ClientID:            "app-a",
		Subject:             "user-42",
		SessionID:           uuid.New(),
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"openid", "profile"},
		Audience:            []string{"api"},
		Nonce:               "n-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ConsentChallengeID:  uuid.New(),
		ExtraClaims:         map[string]any{"role": "admin"},
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
}

func TestAuthorizationCodeRepositoryCreateConsume(t *testing.T) {
	t.Parallel()
	repo := newAuthorizationCodeTestRepo(t)
	ctx := context.Background()
	raw := "raw-auth-code-value-xyz"
	c := sampleAuthorizationCode(t, raw)

	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.Consume(ctx, c.TenantID, c.CodeHash)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.Subject != "user-42" || got.ClientID != "app-a" || got.RedirectURI != c.RedirectURI {
		t.Fatalf("Consume mismatch: %#v", got)
	}
	if got.ExtraClaims["role"] != "admin" {
		t.Fatalf("ExtraClaims: %#v", got.ExtraClaims)
	}

	if _, err := repo.Consume(ctx, c.TenantID, c.CodeHash); !errors.Is(err, domain.ErrAuthorizationCodeUsed) {
		t.Fatalf("second Consume: err=%v, want used", err)
	}
}

func TestAuthorizationCodeRepositoryConsumeMissing(t *testing.T) {
	t.Parallel()
	repo := newAuthorizationCodeTestRepo(t)
	ctx := context.Background()
	if _, err := repo.Consume(ctx, domain.DefaultTenantID, "no-such-hash"); !errors.Is(err, domain.ErrAuthorizationCodeNotFound) {
		t.Fatalf("Consume missing: err=%v, want not found", err)
	}
}

func TestAuthorizationCodeRepositoryCreateRejectsExpired(t *testing.T) {
	t.Parallel()
	repo := newAuthorizationCodeTestRepo(t)
	ctx := context.Background()
	c := sampleAuthorizationCode(t, "expired-code")
	c.ExpiresAt = time.Now().Add(-time.Second)
	if err := repo.Create(ctx, c); err == nil {
		t.Fatal("Create expired: want error")
	}
}
