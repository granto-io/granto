package emailotp

import (
	"context"
	"log/slog"

	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

// User is the identity record needed for login.
type User struct {
	ID    string
	Email string
}

// IdentityBackend resolves an email to a user, creating it when missing.
//
// The engine provides a gRPC-backed implementation via Host.Identity; this
// interface keeps the plugin decoupled from the transport.
type IdentityBackend interface {
	GetOrCreateByEmail(ctx context.Context, email string) (*User, error)
}

// identityAdapter adapts pluginapi.IdentityClient to the plugin's
// IdentityBackend interface.
type identityAdapter struct {
	client pluginapi.IdentityClient
	logger *slog.Logger
}

func newIdentityBackend(client pluginapi.IdentityClient, logger *slog.Logger) IdentityBackend {
	if client == nil {
		return nil
	}
	return &identityAdapter{client: client, logger: logger}
}

func (a *identityAdapter) GetOrCreateByEmail(ctx context.Context, email string) (*User, error) {
	id, normalized, err := a.client.GetOrCreateUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	return &User{ID: id, Email: normalized}, nil
}
