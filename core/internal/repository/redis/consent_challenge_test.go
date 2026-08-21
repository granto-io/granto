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
	"github.com/granto-io/granto/core/internal/repository"
	reporredis "github.com/granto-io/granto/core/internal/repository/redis"
)

func newConsentTestRepo(t *testing.T) *reporredis.ConsentChallengeRepository {
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

	return reporredis.NewConsentChallengeRepository(client)
}

func sampleConsentChallenge(t *testing.T) *domain.ConsentChallenge {
	t.Helper()
	return &domain.ConsentChallenge{
		TenantID:         domain.DefaultTenantID,
		LoginChallengeID: uuid.New(),
		SessionID:        uuid.New(),
		Subject:          "user-42",
		ClientID:         "app-a",
		RequestURL:       "https://auth.example/oauth2/auth?client_id=app-a",
		RedirectURI:      "https://app.example/cb",
		State:            "xyz",
		ResponseType:     "code",
		RequestedScopes:  []string{"openid", "profile"},
		Skip:             false,
		ACR:              "1",
		AMR:              []string{"pwd"},
		Context:          map[string]any{"from": "login"},
		OIDCContext: domain.OIDCContext{
			LoginHint: "user@example.com",
		},
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
}

func TestConsentChallengeRepositoryCreateGetConsumeDefaultMode(t *testing.T) {
	t.Parallel()
	repo := newConsentTestRepo(t)
	ctx := context.Background()
	c := sampleConsentChallenge(t)

	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ID == uuid.Nil || c.AcceptToken == "" {
		t.Fatal("Create left ID or AcceptToken empty")
	}
	token := c.AcceptToken
	id := c.ID

	got, err := repo.Get(ctx, c.TenantID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != "user-42" || got.OIDCContext.LoginHint != "user@example.com" {
		t.Fatalf("Get mismatch: %#v", got)
	}
	if got.AcceptToken != token {
		t.Fatal("Get AcceptToken mismatch")
	}

	if _, err := repo.Consume(ctx, c.TenantID, id, repository.ChallengeConsumeOpts{
		AcceptToken:  "wrong",
		RequireToken: false,
	}); !errors.Is(err, domain.ErrConsentChallengeAcceptTokenInvalid) {
		t.Fatalf("Consume wrong token: err=%v", err)
	}

	consumed, err := repo.Consume(ctx, c.TenantID, id, repository.ChallengeConsumeOpts{
		RequireToken: false,
	})
	if err != nil {
		t.Fatalf("Consume default: %v", err)
	}
	if consumed.ID != id {
		t.Fatalf("Consume ID = %v, want %v", consumed.ID, id)
	}
	if _, err := repo.Get(ctx, c.TenantID, id); !errors.Is(err, domain.ErrConsentChallengeNotFound) {
		t.Fatalf("Get after Consume: %v", err)
	}
}

func TestConsentChallengeRepositoryConsumeStrictMode(t *testing.T) {
	t.Parallel()
	repo := newConsentTestRepo(t)
	ctx := context.Background()
	c := sampleConsentChallenge(t)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	token := c.AcceptToken
	id := c.ID

	if _, err := repo.Consume(ctx, c.TenantID, id, repository.ChallengeConsumeOpts{
		RequireToken: true,
	}); !errors.Is(err, domain.ErrConsentChallengeAcceptTokenInvalid) {
		t.Fatalf("strict empty token: err=%v", err)
	}

	if _, err := repo.Consume(ctx, c.TenantID, id, repository.ChallengeConsumeOpts{
		AcceptToken:  token,
		RequireToken: true,
	}); err != nil {
		t.Fatalf("strict Consume: %v", err)
	}
}

func TestConsentChallengeRepositoryDelete(t *testing.T) {
	t.Parallel()
	repo := newConsentTestRepo(t)
	ctx := context.Background()
	c := sampleConsentChallenge(t)
	if err := repo.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := repo.Delete(ctx, c.TenantID, c.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Delete(ctx, c.TenantID, c.ID); !errors.Is(err, domain.ErrConsentChallengeNotFound) {
		t.Fatalf("Delete twice: err=%v", err)
	}
}
