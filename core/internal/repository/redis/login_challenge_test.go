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

func newTestRepo(t *testing.T) *reporredis.LoginChallengeRepository {
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

	return reporredis.NewLoginChallengeRepository(client)
}

func sampleChallenge(t *testing.T) *domain.LoginChallenge {
	t.Helper()
	return &domain.LoginChallenge{
		TenantID:        domain.DefaultTenantID,
		ClientID:        "app-a",
		RequestURL:      "https://auth.example/oauth2/auth?client_id=app-a",
		RedirectURI:     "https://app.example/cb",
		State:           "xyz",
		ResponseType:    "code",
		RequestedScopes: []string{"openid", "profile"},
		OIDCContext: domain.OIDCContext{
			LoginHint: "user@example.com",
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

func TestLoginChallengeRepositoryCreateGetConsume(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()
	c := sampleChallenge(t)

	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ID == uuid.Nil {
		t.Fatal("Create left ID nil")
	}
	if c.AcceptToken == "" {
		t.Fatal("Create left AcceptToken empty")
	}
	token := c.AcceptToken
	id := c.ID

	got, err := repo.Get(ctx, c.TenantID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != "app-a" || got.OIDCContext.LoginHint != "user@example.com" {
		t.Fatalf("Get mismatch: %#v", got)
	}
	if got.AcceptToken != token {
		t.Fatal("Get AcceptToken mismatch")
	}

	if _, err := repo.Consume(ctx, c.TenantID, id, "wrong"); !errors.Is(err, domain.ErrLoginChallengeAcceptTokenInvalid) {
		t.Fatalf("Consume wrong token: err=%v, want ErrLoginChallengeAcceptTokenInvalid", err)
	}
	// Wrong token must leave challenge in place.
	if _, err := repo.Get(ctx, c.TenantID, id); err != nil {
		t.Fatalf("Get after bad Consume: %v", err)
	}

	consumed, err := repo.Consume(ctx, c.TenantID, id, token)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.ID != id {
		t.Fatalf("Consume ID = %v, want %v", consumed.ID, id)
	}
	if _, err := repo.Get(ctx, c.TenantID, id); !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Fatalf("Get after Consume: err=%v, want not found", err)
	}
}

func TestLoginChallengeRepositoryDelete(t *testing.T) {
	t.Parallel()
	repo := newTestRepo(t)
	ctx := context.Background()
	c := sampleChallenge(t)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Delete(ctx, c.TenantID, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, c.TenantID, c.ID); !errors.Is(err, domain.ErrLoginChallengeNotFound) {
		t.Fatalf("Delete twice: err=%v, want not found", err)
	}
}
