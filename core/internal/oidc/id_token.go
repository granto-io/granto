package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/keys"
)

// IDTokens issues OpenID Connect ID Tokens.
type IDTokens struct {
	cfg  *config.Config
	keys *keys.Manager
}

// NewIDTokens constructs an ID Token issuer.
func NewIDTokens(cfg *config.Config, keyMgr *keys.Manager) *IDTokens {
	return &IDTokens{cfg: cfg, keys: keyMgr}
}

// IssueInput is the data needed to mint an id_token.
type IssueInput struct {
	ClientID   string
	Subject    string
	SessionID  uuid.UUID
	AuthTime   time.Time
	Nonce      string
	Scopes     []string
	Extra      map[string]any
	IDTokenTTL *time.Duration
}

// Issue returns a signed ID Token when openid is in scopes; otherwise "".
func (s *IDTokens) Issue(_ context.Context, in IssueInput) (string, error) {
	if s == nil || s.keys == nil {
		return "", nil
	}
	if !containsScope(in.Scopes, "openid") {
		return "", nil
	}
	if in.Subject == "" || in.ClientID == "" {
		return "", fmt.Errorf("subject and client_id are required for id_token")
	}

	now := time.Now().UTC()
	ttl := s.cfg.Token.IDTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if in.IDTokenTTL != nil && *in.IDTokenTTL > 0 {
		ttl = *in.IDTokenTTL
	}

	authTime := in.AuthTime
	if authTime.IsZero() {
		authTime = now
	}

	claims := jwt.MapClaims{
		"iss":       strings.TrimRight(s.cfg.Token.Issuer, "/"),
		"sub":       in.Subject,
		"aud":       in.ClientID,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"auth_time": authTime.Unix(),
		"jti":       uuid.NewString(),
	}
	if in.SessionID != uuid.Nil {
		claims["sid"] = in.SessionID.String()
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}

	mergeIDTokenExtra(claims, in.Extra)

	signed, err := s.keys.SignJWT(claims)
	if err != nil {
		return "", fmt.Errorf("sign id_token: %w", err)
	}
	return signed, nil
}

// ParseHint verifies an id_token_hint signature (exp may be ignored by the key parser).
func (s *IDTokens) ParseHint(raw string) (jwt.MapClaims, error) {
	if s == nil || s.keys == nil {
		return nil, fmt.Errorf("id token verifier not configured")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty id_token_hint")
	}
	return s.keys.ParseJWT(raw)
}

func mergeIDTokenExtra(claims jwt.MapClaims, extra map[string]any) {
	if extra == nil {
		return
	}
	if nested, ok := extra["id_token"].(map[string]any); ok {
		for k, v := range nested {
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

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
