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

func newTokenTestRepo(t *testing.T) *reporredis.TokenRepository {
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

	return reporredis.NewTokenRepository(client)
}

func TestTokenRepositoryAccessTokenCreateGetRevoke(t *testing.T) {
	t.Parallel()
	repo := newTokenTestRepo(t)
	ctx := context.Background()
	raw := "access-raw-token"
	at := &domain.AccessToken{
		TokenHash: domain.HashToken(raw),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-42",
		SessionID: uuid.New(),
		Scopes:    []string{"openid"},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := repo.CreateAccessToken(ctx, at); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	got, err := repo.GetAccessToken(ctx, at.TenantID, at.TokenHash)
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if got.Subject != "user-42" || got.JTI != at.JTI {
		t.Fatalf("GetAccessToken mismatch: %#v", got)
	}

	if err := repo.RevokeAccessToken(ctx, at.TenantID, at.TokenHash); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}
	if _, err := repo.GetAccessToken(ctx, at.TenantID, at.TokenHash); !errors.Is(err, domain.ErrAccessTokenNotFound) {
		t.Fatalf("Get after revoke: err=%v", err)
	}

	at2 := &domain.AccessToken{
		TokenHash: domain.HashToken("access-raw-2"),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-42",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := repo.CreateAccessToken(ctx, at2); err != nil {
		t.Fatalf("CreateAccessToken 2: %v", err)
	}
	if err := repo.RevokeAccessTokenByJTI(ctx, at2.TenantID, at2.JTI); err != nil {
		t.Fatalf("RevokeAccessTokenByJTI: %v", err)
	}
	if _, err := repo.GetAccessToken(ctx, at2.TenantID, at2.TokenHash); !errors.Is(err, domain.ErrAccessTokenNotFound) {
		t.Fatalf("Get after ByJTI revoke: err=%v", err)
	}
}

func TestTokenRepositoryRefreshTokenRotateAndRevokeBySession(t *testing.T) {
	t.Parallel()
	repo := newTokenTestRepo(t)
	ctx := context.Background()
	sessionID := uuid.New()
	oldRaw := "refresh-old"
	old := &domain.RefreshToken{
		TokenHash: domain.HashToken(oldRaw),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-42",
		SessionID: sessionID,
		Scopes:    []string{"openid", "offline"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := repo.CreateRefreshToken(ctx, old); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	next := &domain.RefreshToken{
		TokenHash: domain.HashToken("refresh-new"),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-42",
		SessionID: sessionID,
		Scopes:    []string{"openid", "offline"},
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := repo.RotateRefreshToken(ctx, old.TenantID, old.TokenHash, next); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if _, err := repo.GetRefreshToken(ctx, old.TenantID, old.TokenHash); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("old after rotate: err=%v", err)
	}
	got, err := repo.GetRefreshToken(ctx, next.TenantID, next.TokenHash)
	if err != nil {
		t.Fatalf("new after rotate: %v", err)
	}
	if got.JTI != next.JTI {
		t.Fatalf("rotated JTI = %q, want %q", got.JTI, next.JTI)
	}

	if err := repo.RevokeRefreshTokensBySession(ctx, next.TenantID, sessionID); err != nil {
		t.Fatalf("RevokeRefreshTokensBySession: %v", err)
	}
	if _, err := repo.GetRefreshToken(ctx, next.TenantID, next.TokenHash); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("after session revoke: err=%v", err)
	}
}
