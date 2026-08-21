package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ChallengeConsumeOpts controls Accept-time checks for login/consent challenges.
type ChallengeConsumeOpts struct {
	// AcceptToken from the Accept* caller (may be empty in default mode).
	AcceptToken string
	// RequireToken when true (admin.accept_strict): AcceptToken must match.
	// When false: empty AcceptToken is allowed; a non-empty wrong token is still rejected.
	RequireToken bool
}

// LoginChallengeConsumeOpts is an alias kept for existing call sites.
type LoginChallengeConsumeOpts = ChallengeConsumeOpts

// LoginChallengeRepository persists short-lived login challenges (Redis).
type LoginChallengeRepository interface {
	// Create stores the challenge. Empty ID / AcceptToken are generated.
	// ExpiresAt must be in the future (TTL for Redis key).
	Create(ctx context.Context, challenge *domain.LoginChallenge) error

	// Get returns the challenge including AcceptToken (for authenticated GetLogin).
	Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.LoginChallenge, error)

	// Consume loads and deletes the challenge. Token rules: see ChallengeConsumeOpts.
	Consume(ctx context.Context, tenantID, id uuid.UUID, opts ChallengeConsumeOpts) (*domain.LoginChallenge, error)

	// Delete removes the challenge (e.g. RejectLogin) without returning it.
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}
