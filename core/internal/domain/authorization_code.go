package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// AuthorizationCode is a short-lived OAuth 2.0 authorization code session.
// Only CodeHash is stored (never the raw code from the redirect). Redis only.
type AuthorizationCode struct {
	CodeHash string
	TenantID uuid.UUID

	ClientID  string
	Subject   string
	SessionID uuid.UUID

	RedirectURI string
	Scopes      []string
	Audience    []string

	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string

	ConsentChallengeID uuid.UUID

	// ExtraClaims carries session data from AcceptConsent for token / ID token issuance.
	ExtraClaims map[string]any

	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the code is past ExpiresAt.
func (c *AuthorizationCode) IsExpired() bool {
	if c == nil {
		return true
	}
	return !c.ExpiresAt.After(time.Now())
}

// HashAuthorizationCode returns SHA-256 hex of the raw authorization code.
func HashAuthorizationCode(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
