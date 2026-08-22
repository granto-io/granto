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

func newFlowVerifierTestRepo(t *testing.T) *reporredis.FlowVerifierRepository {
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

	return reporredis.NewFlowVerifierRepository(client)
}

func sampleFlowVerifier(t *testing.T, kind domain.FlowVerifierKind) *domain.FlowVerifier {
	t.Helper()
	return &domain.FlowVerifier{
		TenantID:   domain.DefaultTenantID,
		Kind:       kind,
		SessionID:  uuid.New(),
		RedirectTo: "https://app.example/cb?code=abc&state=xyz",
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
}

func TestFlowVerifierRepositoryCreateConsume(t *testing.T) {
	t.Parallel()
	repo := newFlowVerifierTestRepo(t)
	ctx := context.Background()
	v := sampleFlowVerifier(t, domain.FlowVerifierKindConsent)

	if err := repo.Create(ctx, v); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if v.ID == uuid.Nil {
		t.Fatal("Create left ID empty")
	}
	if v.Kind.QueryParam() != "consent_verifier" {
		t.Fatalf("QueryParam = %q", v.Kind.QueryParam())
	}
	id := v.ID
	sessionID := v.SessionID

	got, err := repo.Consume(ctx, v.TenantID, id)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.SessionID != sessionID || got.RedirectTo != v.RedirectTo || got.Kind != domain.FlowVerifierKindConsent {
		t.Fatalf("Consume mismatch: %#v", got)
	}

	if _, err := repo.Consume(ctx, v.TenantID, id); !errors.Is(err, domain.ErrFlowVerifierNotFound) {
		t.Fatalf("second Consume: err=%v, want not found", err)
	}
}

func TestFlowVerifierRepositoryCreateRejectsBadKind(t *testing.T) {
	t.Parallel()
	repo := newFlowVerifierTestRepo(t)
	ctx := context.Background()
	v := sampleFlowVerifier(t, "nope")
	if err := repo.Create(ctx, v); err == nil {
		t.Fatal("Create bad kind: want error")
	}
}

func TestFlowVerifierRepositoryCreateRejectsExpired(t *testing.T) {
	t.Parallel()
	repo := newFlowVerifierTestRepo(t)
	ctx := context.Background()
	v := sampleFlowVerifier(t, domain.FlowVerifierKindLogin)
	v.ExpiresAt = time.Now().Add(-time.Second)
	if err := repo.Create(ctx, v); err == nil {
		t.Fatal("Create expired: want error")
	}
}
