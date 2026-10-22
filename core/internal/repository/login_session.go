package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// LoginSessionRepository persists AS authentication sessions (SSO cookie / sid).
type LoginSessionRepository interface {
	Create(ctx context.Context, session *domain.LoginSession) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.LoginSession, error)
	ListBySubject(ctx context.Context, tenantID uuid.UUID, subject string) ([]*domain.LoginSession, error)
	// ListByDeviceID returns sessions for the same browser device and subject
	// (device logout must not cross users on a shared machine).
	ListByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID, subject string) ([]*domain.LoginSession, error)
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteBySubject(ctx context.Context, tenantID uuid.UUID, subject string) error
}
