package domain

import (
	"crypto/subtle"
	"time"

	"github.com/google/uuid"
)

// ConsentChallenge is a short-lived snapshot after login while the user grants
// scopes to a client. Stored in Redis (not Postgres).
//
// Public URL carries only ID. AcceptToken is always generated and returned by
// authenticated GetConsent; whether AcceptConsent must present it depends on
// admin.accept_strict (default off = Hydra-compatible; see project decisions).
type ConsentChallenge struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	LoginChallengeID uuid.UUID
	SessionID        uuid.UUID
	Subject          string
	ClientID         string

	RequestURL          string
	RedirectURI         string
	State               string
	ResponseType        string
	RequestedScopes     []string
	RequestedAudience   []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string

	Skip bool
	ACR  string
	AMR  []string

	// Context is arbitrary data from AcceptLogin for the consent UI / token claims.
	Context map[string]any

	OIDCContext OIDCContext

	// AcceptToken is a high-entropy secret. Never put it in the browser redirect query.
	// Required on Accept only when admin.accept_strict is enabled.
	AcceptToken string

	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the challenge is past ExpiresAt.
func (c *ConsentChallenge) IsExpired() bool {
	if c == nil {
		return true
	}
	return !c.ExpiresAt.After(time.Now())
}

// ValidAcceptToken reports whether got matches AcceptToken (constant-time).
func (c *ConsentChallenge) ValidAcceptToken(got string) bool {
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
