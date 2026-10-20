package oauth2

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/domain"
)

func (f *Flow) authenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	if clientID == "" {
		return nil, ErrInvalidClient
	}
	client, err := f.clients.GetByClientID(ctx, f.tenantID(), clientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	if client.IsPublic() || client.TokenEndpointAuthMethod == domain.TokenEndpointAuthNone {
		return client, nil
	}
	if clientSecret == "" || client.ClientSecretHash == "" {
		return nil, ErrInvalidClientSecret
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		return nil, ErrInvalidClientSecret
	}
	return client, nil
}
