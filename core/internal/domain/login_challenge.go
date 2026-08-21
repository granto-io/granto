package domain

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// LoginChallenge is a short-lived snapshot of an /oauth2/auth request while the
// user authenticates in the consent module. Stored in Redis (not Postgres).
//
// Public URL carries only ID. AcceptToken is always generated and returned by
// authenticated GetLogin; whether AcceptLogin must present it depends on
// admin.accept_strict (default off = Hydra-compatible; see project decisions).
type LoginChallenge struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	ClientID            string
	RequestURL          string
	RedirectURI         string
	State               string
	ResponseType        string
	RequestedScopes     []string
	RequestedAudience   []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string

	// SessionID is set when a login session cookie was already present (uuid.Nil if none).
	SessionID uuid.UUID
	Skip      bool

	OIDCContext OIDCContext

	// AcceptToken is a high-entropy secret. Never put it in the browser redirect query.
	// Required on Accept only when admin.accept_strict is enabled.
	AcceptToken string

	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the challenge is past ExpiresAt.
func (c *LoginChallenge) IsExpired() bool {
	if c == nil {
		return true
	}
	return !c.ExpiresAt.After(time.Now())
}

// ValidAcceptToken reports whether got matches AcceptToken (constant-time).
func (c *LoginChallenge) ValidAcceptToken(got string) bool {
	if c == nil {
		return false
	}
	a := []byte(c.AcceptToken)
	b := []byte(got)
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// NewAcceptToken generates a 256-bit hex accept token.
func NewAcceptToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
