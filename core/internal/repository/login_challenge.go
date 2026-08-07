package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// LoginChallengeRepository persists short-lived login challenges (Redis).
type LoginChallengeRepository interface {
	// Create stores the challenge. Empty ID / AcceptToken are generated.
	// ExpiresAt must be in the future (TTL for Redis key).
	Create(ctx context.Context, challenge *domain.LoginChallenge) error

	// Get returns the challenge including AcceptToken (for authenticated GetLogin).
	Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.LoginChallenge, error)

	// Consume atomically loads and deletes the challenge if acceptToken matches.
	Consume(ctx context.Context, tenantID, id uuid.UUID, acceptToken string) (*domain.LoginChallenge, error)

	// Delete removes the challenge (e.g. RejectLogin) without returning it.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}
