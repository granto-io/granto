package domain

import (
	"time"

	"github.com/google/uuid"
)

// LoginSession is the AS authentication session for a browser ("who is logged in").
// It is not tied to a single OAuth client and does not store granted scopes —
// those belong to consent / authorization code. Cookie / OIDC sid = ID.
type LoginSession struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	Subject         string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Remember        bool

	// DeviceID binds the session to a browser device cookie (granto_did).
	// Empty for legacy sessions or non-browser flows.
	DeviceID string

	ACR                       string
	AMR                       []string
	IdentityProviderSessionID string
	Metadata                  map[string]any

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsExpired reports whether the session is past ExpiresAt.
func (s *LoginSession) IsExpired() bool {
	if s == nil {
		return true
	}
	return !s.ExpiresAt.After(time.Now())
}
