package oauth2

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/granto-io/granto/core/internal/domain"
)

// UserInfo returns OIDC UserInfo claims for a valid opaque access token
// that includes the openid scope (OIDC Core §5.3).
func (f *Flow) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	raw := strings.TrimSpace(accessToken)
	if raw == "" {
		return nil, ErrInvalidToken
	}
	at, err := f.tokens.GetAccessToken(ctx, f.tenantID(), domain.HashToken(raw))
	if at == nil || errors.Is(err, domain.ErrAccessTokenNotFound) {
		return nil, ErrInvalidToken
	}
	if errors.Is(err, domain.ErrAccessTokenExpired) || at.IsExpired() {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	if !containsScope(at.Scopes, "openid") {
		return nil, ErrInsufficientScope
	}

	claims := map[string]any{
		"sub": at.Subject,
	}
	mergeUserInfoExtra(claims, at.Extra)
	return claims, nil
}

func containsScope(scopes []string, want string) bool {
	return slices.Contains(scopes, want)
}

// mergeUserInfoExtra copies consent-session claims into the UserInfo response.
// Prefer nested Extra["id_token"] (AcceptConsent session.id_token); also accept
// top-level standard claim keys if present on Extra.
func mergeUserInfoExtra(claims map[string]any, extra map[string]any) {
	if extra == nil {
		return
	}
	if nested, ok := extra["id_token"].(map[string]any); ok {
		for k, v := range nested {
			if k == "sub" {
				continue // subject comes from the access token
			}
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}
	for _, claim := range []string{
		"name", "given_name", "family_name", "middle_name",
		"nickname", "preferred_username", "profile", "picture",
		"website", "email", "email_verified", "gender",
		"birthdate", "zoneinfo", "locale", "phone_number",
		"phone_number_verified", "address", "updated_at",
	} {
		if v, ok := extra[claim]; ok {
			if _, exists := claims[claim]; !exists {
				claims[claim] = v
			}
		}
	}
}
