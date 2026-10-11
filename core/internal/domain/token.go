package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// AccessToken is an opaque access-token session. Raw token is never stored — only TokenHash.
type AccessToken struct {
	TokenHash string
	JTI       string
	TenantID  uuid.UUID

	ClientID  string
	Subject   string
	SessionID uuid.UUID

	Scopes   []string
	Audience []string
	Extra    map[string]any

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the access token is past ExpiresAt.
func (t *AccessToken) IsExpired() bool {
	if t == nil {
		return true
	}
	return !t.ExpiresAt.After(time.Now())
}

// RefreshToken is an opaque refresh-token session. Raw token is never stored — only TokenHash.
type RefreshToken struct {
	TokenHash string
	JTI       string
	TenantID  uuid.UUID

	ClientID  string
	Subject   string
	SessionID uuid.UUID

	Scopes   []string
	Audience []string
	Extra    map[string]any

	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the refresh token is past ExpiresAt.
func (t *RefreshToken) IsExpired() bool {
	if t == nil {
		return true
	}
	return !t.ExpiresAt.After(time.Now())
}

// HashToken returns SHA-256 hex of a raw opaque token (access or refresh).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
