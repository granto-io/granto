package oauth2

import (
	"context"
	"fmt"

	"github.com/granto-io/granto/core/internal/domain"
)

// ClientCredentialsInput is grant_type=client_credentials (RFC 6749 §4.4).
type ClientCredentialsInput struct {
	ClientID     string
	ClientSecret string
	Scope        string
}

// ClientCredentials authenticates a confidential client and issues an opaque access token.
// No refresh token and no ID Token. Subject is the client_id.
func (f *Flow) ClientCredentials(ctx context.Context, in ClientCredentialsInput) (*TokenResponse, error) {
	client, err := f.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	if client.IsPublic() || client.TokenEndpointAuthMethod == domain.TokenEndpointAuthNone {
		f.auditTokenFailure(ctx, in.ClientID, "unauthorized_client", map[string]any{"reason": "public_or_none_auth"})
		return nil, ErrUnauthorizedClient
	}
	if !client.HasGrantType(domain.GrantTypeClientCredentials) {
		f.auditTokenFailure(ctx, in.ClientID, "unauthorized_client", map[string]any{"reason": "grant_type_not_allowed"})
		return nil, ErrUnauthorizedClient
	}

	scopes := parseSpaceList(in.Scope)
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.DefaultScopes...)
	}
	for _, scope := range scopes {
		if !client.HasScope(scope) {
			f.auditTokenFailure(ctx, in.ClientID, "invalid_scope", map[string]any{"reason": "scope_not_allowed", "scope": scope})
			return nil, fmt.Errorf("%w: %s", ErrInvalidScope, scope)
		}
	}

	return f.issueTokens(ctx, client, issueTokenOpts{
		subject:     client.ClientID,
		scopes:      scopes,
		audience:    append([]string(nil), client.Audience...),
		skipRefresh: true,
		skipIDToken: true,
	})
}
