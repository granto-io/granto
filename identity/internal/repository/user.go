package repository

import (
	"context"

	"github.com/granto-io/granto/identity/internal/domain"
)

// UserRepository persists identity users.
type UserRepository interface {
	// GetByEmail returns the user for an email, or domain.ErrUserNotFound.
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	// GetOrCreateByEmail returns the existing user or creates a new one
	// (without a password) for the email.
	GetOrCreateByEmail(ctx context.Context, email string) (*domain.User, error)
	// Create inserts a new user. Returns domain.ErrEmailTaken on conflict.
	Create(ctx context.Context, user *domain.User) error
	// SetPassword stores a bcrypt password hash for the user.
	SetPassword(ctx context.Context, id string, passwordHash string) error
}
