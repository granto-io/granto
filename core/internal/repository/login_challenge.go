package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// LoginChallengeConsumeOpts controls Accept-time checks (D-022).
type LoginChallengeConsumeOpts struct {
	// AcceptToken from the AcceptLogin caller (may be empty in default mode).
	AcceptToken string
	// RequireToken when true (admin.accept_strict): AcceptToken must match.
	// When false: empty AcceptToken is allowed; a non-empty wrong token is still rejected.
	RequireToken bool
}

// LoginChallengeRepository persists short-lived login challenges (Redis).
type LoginChallengeRepository interface {
	// Create stores the challenge. Empty ID / AcceptToken are generated.
	// ExpiresAt must be in the future (TTL for Redis key).
	Create(ctx context.Context, challenge *domain.LoginChallenge) error

	// Get returns the challenge including AcceptToken (for authenticated GetLogin).
	Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.LoginChallenge, error)

	// Consume loads and deletes the challenge. Token rules: see LoginChallengeConsumeOpts.
	Consume(ctx context.Context, tenantID, id uuid.UUID, opts LoginChallengeConsumeOpts) (*domain.LoginChallenge, error)

	// Delete removes the challenge (e.g. RejectLogin) without returning it.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}
