package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// AuthorizationCodeRepository persists short-lived authorization codes (Redis).
type AuthorizationCodeRepository interface {
	// Create stores the code by CodeHash. ExpiresAt must be in the future (TTL).
	Create(ctx context.Context, code *domain.AuthorizationCode) error

	// Consume loads and invalidates the code. Distinguishes replay (Used) from missing.
	Consume(ctx context.Context, tenantID uuid.UUID, codeHash string) (*domain.AuthorizationCode, error)
}
