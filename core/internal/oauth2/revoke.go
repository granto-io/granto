package oauth2

import (
	"context"
	"errors"
	"strings"

	"github.com/granto-io/granto/core/internal/domain"
)

// RevokeInput is POST /oauth2/revoke (RFC 7009).
type RevokeInput struct {
	ClientID      string
	ClientSecret  string
	Token         string
	TokenTypeHint string // "access_token" | "refresh_token" | ""
}

// Revoke invalidates an opaque access or refresh token.
// Unknown / foreign-client tokens succeed with no effect (RFC 7009 §2.2).
func (f *Flow) Revoke(ctx context.Context, in RevokeInput) error {
	client, err := f.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return err
	}
	if strings.TrimSpace(in.Token) == "" {
		return nil
	}

	hash := domain.HashToken(in.Token)
	hint := strings.ToLower(strings.TrimSpace(in.TokenTypeHint))

	switch hint {
	case "refresh_token":
		if f.revokeRefreshIfOwned(ctx, client.ClientID, hash) {
			return nil
		}
		_ = f.revokeAccessIfOwned(ctx, client.ClientID, hash)
	case "access_token":
		if f.revokeAccessIfOwned(ctx, client.ClientID, hash) {
			return nil
		}
		_ = f.revokeRefreshIfOwned(ctx, client.ClientID, hash)
	default:
		if f.revokeAccessIfOwned(ctx, client.ClientID, hash) {
			return nil
		}
		_ = f.revokeRefreshIfOwned(ctx, client.ClientID, hash)
	}
	return nil
}

func (f *Flow) revokeAccessIfOwned(ctx context.Context, clientID, hash string) bool {
	at, err := f.tokens.GetAccessToken(ctx, f.tenantID(), hash)
	if at == nil {
		return false
	}
	if err != nil && !errors.Is(err, domain.ErrAccessTokenExpired) {
		return false
	}
	if at.ClientID != clientID {
		return false
	}
	_ = f.tokens.RevokeAccessToken(ctx, f.tenantID(), hash)
	return true
}

func (f *Flow) revokeRefreshIfOwned(ctx context.Context, clientID, hash string) bool {
	rt, err := f.tokens.GetRefreshToken(ctx, f.tenantID(), hash)
	if rt == nil {
		return false
	}
	if err != nil && !errors.Is(err, domain.ErrRefreshTokenExpired) {
		return false
	}
	if rt.ClientID != clientID {
		return false
	}
	_ = f.tokens.RevokeRefreshToken(ctx, f.tenantID(), hash)
	return true
}
