package domain

import (
	"time"

	"github.com/google/uuid"
)

// ConsentGrant is a remembered consent for (subject, client) — Postgres.
// When present and covering requested scopes, the AS may skip the consent UI.
type ConsentGrant struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	Subject  string
	ClientID string

	Scopes   []string
	Audience []string

	// ExpiresAt nil means the grant does not expire.
	ExpiresAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsExpired reports whether the grant is past ExpiresAt.
func (g *ConsentGrant) IsExpired() bool {
	if g == nil {
		return true
	}
	if g.ExpiresAt == nil {
		return false
	}
	return !g.ExpiresAt.After(time.Now())
}

// CoversScopes reports whether every requested scope is in the grant.
func (g *ConsentGrant) CoversScopes(requested []string) bool {
	if g == nil || g.IsExpired() {
		return false
	}
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(g.Scopes))
	for _, s := range g.Scopes {
		set[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// CoversAudience reports whether every requested audience is in the grant.
// Empty requested audience always passes. Empty grant audience only passes when
// the request is also empty.
func (g *ConsentGrant) CoversAudience(requested []string) bool {
	if g == nil || g.IsExpired() {
		return false
	}
	if len(requested) == 0 {
		return true
	}
	if len(g.Audience) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(g.Audience))
	for _, a := range g.Audience {
		set[a] = struct{}{}
	}
	for _, a := range requested {
		if _, ok := set[a]; !ok {
			return false
		}
	}
	return true
}
