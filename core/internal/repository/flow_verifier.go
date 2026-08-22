package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// FlowVerifierRepository persists one-shot browser handoff verifiers (Redis).
type FlowVerifierRepository interface {
	// Create stores the verifier. Empty ID is generated. Kind and RedirectTo required;
	// ExpiresAt must be in the future (TTL for Redis key).
	Create(ctx context.Context, verifier *domain.FlowVerifier) error

	// Consume loads and deletes the verifier (single-use).
	Consume(ctx context.Context, tenantID, id uuid.UUID) (*domain.FlowVerifier, error)
}
