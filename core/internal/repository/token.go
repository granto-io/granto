package repository

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// TokenRepository persists opaque access and refresh token sessions (Redis).
type TokenRepository interface {
	CreateAccessToken(ctx context.Context, token *domain.AccessToken) error
	GetAccessToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*domain.AccessToken, error)
	RevokeAccessToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) error
	RevokeAccessTokenByJTI(ctx context.Context, tenantID uuid.UUID, jti string) error

	CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) (*domain.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, tenantID uuid.UUID, oldHash string, next *domain.RefreshToken) error
	RevokeRefreshToken(ctx context.Context, tenantID uuid.UUID, tokenHash string) error
	RevokeRefreshTokensBySession(ctx context.Context, tenantID, sessionID uuid.UUID) error
}
