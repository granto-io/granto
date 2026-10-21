package oauth2

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// IntrospectInput is POST /oauth2/introspect (RFC 7662).
type IntrospectInput struct {
	ClientID      string
	ClientSecret  string
	Token         string
	TokenTypeHint string
}

// IntrospectionResponse is the RFC 7662 introspection body.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	Sid       string   `json:"sid,omitempty"`
}

// Introspect reports whether an opaque token is active and returns metadata.
func (f *Flow) Introspect(ctx context.Context, in IntrospectInput) (*IntrospectionResponse, error) {
	client, err := f.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	inactive := &IntrospectionResponse{Active: false}
	if strings.TrimSpace(in.Token) == "" {
		return inactive, nil
	}

	hash := domain.HashToken(in.Token)
	hint := strings.ToLower(strings.TrimSpace(in.TokenTypeHint))

	switch hint {
	case "refresh_token":
		if resp := f.introspectRefresh(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
		if resp := f.introspectAccess(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
	case "access_token":
		if resp := f.introspectAccess(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
		if resp := f.introspectRefresh(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
	default:
		if resp := f.introspectAccess(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
		if resp := f.introspectRefresh(ctx, client.ClientID, hash); resp != nil {
			return resp, nil
		}
	}
	return inactive, nil
}

func (f *Flow) introspectAccess(ctx context.Context, clientID, hash string) *IntrospectionResponse {
	at, err := f.tokens.GetAccessToken(ctx, f.tenantID(), hash)
	if at == nil {
		return nil
	}
	if at.ClientID != clientID {
		return &IntrospectionResponse{Active: false}
	}
	if err != nil {
		return &IntrospectionResponse{Active: false}
	}
	return &IntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(at.Scopes, " "),
		ClientID:  at.ClientID,
		TokenType: "Bearer",
		Exp:       at.ExpiresAt.Unix(),
		Iat:       at.IssuedAt.Unix(),
		Sub:       at.Subject,
		Aud:       at.Audience,
		Iss:       f.issuer(),
		JTI:       at.JTI,
		Sid:       sidString(at.SessionID),
	}
}

func (f *Flow) introspectRefresh(ctx context.Context, clientID, hash string) *IntrospectionResponse {
	rt, err := f.tokens.GetRefreshToken(ctx, f.tenantID(), hash)
	if rt == nil {
		return nil
	}
	if rt.ClientID != clientID {
		return &IntrospectionResponse{Active: false}
	}
	if err != nil {
		return &IntrospectionResponse{Active: false}
	}
	return &IntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(rt.Scopes, " "),
		ClientID:  rt.ClientID,
		TokenType: "refresh_token",
		Exp:       rt.ExpiresAt.Unix(),
		Iat:       rt.IssuedAt.Unix(),
		Sub:       rt.Subject,
		Aud:       rt.Audience,
		Iss:       f.issuer(),
		JTI:       rt.JTI,
		Sid:       sidString(rt.SessionID),
	}
}

func sidString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}
