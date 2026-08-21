package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ConsentChallengeRepository persists short-lived consent challenges (Redis).
type ConsentChallengeRepository interface {
	Create(ctx context.Context, challenge *domain.ConsentChallenge) error
	Get(ctx context.Context, tenantID, id uuid.UUID) (*domain.ConsentChallenge, error)
	Consume(ctx context.Context, tenantID, id uuid.UUID, opts ChallengeConsumeOpts) (*domain.ConsentChallenge, error)
	Delete(ctx context.Context, tenantID, id uuid.UUID) error
}
