package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ClientRepository persists OAuth2 / OIDC / GNAP clients.
type ClientRepository interface {
	GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*domain.Client, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	List(ctx context.Context, tenantID uuid.UUID, filter ClientFilter) ([]*domain.Client, error)
	Create(ctx context.Context, client *domain.Client) error
	Update(ctx context.Context, client *domain.Client) error
	Delete(ctx context.Context, id uuid.UUID) error // soft delete
}

// ClientFilter holds list/search parameters.
type ClientFilter struct {
	Limit  int
	Offset int
	Search string // name or client_id (ILIKE)
}
