package domain_test

import (
	"testing"
	"time"

	"github.com/granto-io/granto/core/internal/domain"
)

func TestConsentGrantCovers(t *testing.T) {
	t.Parallel()
	g := &domain.ConsentGrant{
		Scopes:   []string{"openid", "profile"},
		Audience: []string{"api"},
	}
	if !g.CoversScopes([]string{"openid"}) || !g.CoversScopes(nil) {
		t.Fatal("CoversScopes failed")
	}
	if g.CoversScopes([]string{"email"}) {
		t.Fatal("unexpected cover email")
	}
	if !g.CoversAudience(nil) || !g.CoversAudience([]string{"api"}) {
		t.Fatal("CoversAudience failed")
	}
	if g.CoversAudience([]string{"other"}) {
		t.Fatal("unexpected cover other audience")
	}
	exp := time.Now().Add(-time.Minute)
	g.ExpiresAt = &exp
	if g.CoversScopes([]string{"openid"}) {
		t.Fatal("expired grant should not cover")
	}
}
