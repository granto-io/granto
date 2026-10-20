package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// SigningKeyRepository persists AS signing keys (Postgres).
type SigningKeyRepository interface {
	GetActiveKey(ctx context.Context, tenantID uuid.UUID, algorithm string) (*domain.SigningKey, error)
	ListActiveKeys(ctx context.Context, tenantID uuid.UUID) ([]*domain.SigningKey, error)
	Create(ctx context.Context, key *domain.SigningKey) error
}
