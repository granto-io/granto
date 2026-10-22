package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ClientRepository persists OAuth2 / OIDC / GNAP clients.
// GetByID / Update / Delete are always scoped by tenant_id (no cross-tenant access by UUID alone).
type ClientRepository interface {
	GetByClientID(ctx context.Context, tenantID uuid.UUID, clientID string) (*domain.Client, error)
	GetByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Client, error)
	List(ctx context.Context, tenantID uuid.UUID, filter ClientFilter) ([]*domain.Client, error)
	Create(ctx context.Context, client *domain.Client) error
	Update(ctx context.Context, client *domain.Client) error  // WHERE id AND tenant_id
	Delete(ctx context.Context, tenantID, id uuid.UUID) error // soft delete
}

// ClientFilter holds list/search parameters.
type ClientFilter struct {
	Limit  int
	Offset int
	Search string // name or client_id (ILIKE)
}
