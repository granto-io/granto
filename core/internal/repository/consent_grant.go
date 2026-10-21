package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ConsentGrantRepository persists remembered consents (Postgres).
type ConsentGrantRepository interface {
	Upsert(ctx context.Context, grant *domain.ConsentGrant) error
	Get(ctx context.Context, tenantID uuid.UUID, subject, clientID string) (*domain.ConsentGrant, error)
	Delete(ctx context.Context, tenantID uuid.UUID, subject, clientID string) error
}
