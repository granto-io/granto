package domain

import (
	"time"

	"github.com/google/uuid"
)

// FlowVerifierKind distinguishes login vs consent browser handoff.
type FlowVerifierKind string

const (
	FlowVerifierKindLogin   FlowVerifierKind = "login"
	FlowVerifierKindConsent FlowVerifierKind = "consent"
)

// FlowVerifier is a one-shot bridge after AcceptLogin / AcceptConsent:
// consent redirects the browser to the AS with login_verifier or consent_verifier;
// AS consumes the verifier, sets the SSO cookie, then redirects to RedirectTo.
// Stored in Redis (not Postgres).
type FlowVerifier struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	Kind      FlowVerifierKind
	SessionID uuid.UUID
	// RedirectTo is the next hop (consent UI after login, or client callback after consent).
	RedirectTo string

	ExpiresAt time.Time
	CreatedAt time.Time
}

// QueryParam is the Hydra-compatible public query name for this kind.
func (k FlowVerifierKind) QueryParam() string {
	switch k {
	case FlowVerifierKindConsent:
		return "consent_verifier"
	default:
		return "login_verifier"
	}
}

// IsExpired reports whether the verifier is past ExpiresAt.
func (v *FlowVerifier) IsExpired() bool {
	if v == nil {
		return true
	}
	return !v.ExpiresAt.After(time.Now())
}

// ValidKind reports whether Kind is a known value.
func (v *FlowVerifier) ValidKind() bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case FlowVerifierKindLogin, FlowVerifierKindConsent:
		return true
	default:
		return false
	}
}
