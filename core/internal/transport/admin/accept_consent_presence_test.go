package admin

import (
	"testing"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/oauth2"
)

// Mirrors AcceptConsentRequest mapping: presence flag OR non-nil slice (REST/JSON).
func acceptConsentPresence(body *adminv1.AcceptConsentBody) (scopeSet, audSet bool) {
	return body.GetGrantScopeSet() || body.GrantScope != nil,
		body.GetGrantAccessTokenAudienceSet() || body.GrantAccessTokenAudience != nil
}

func TestAcceptConsentPresenceMapping(t *testing.T) {
	t.Parallel()

	t.Run("omitted repeated → unset", func(t *testing.T) {
		body := &adminv1.AcceptConsentBody{}
		scopeSet, audSet := acceptConsentPresence(body)
		if scopeSet || audSet {
			t.Fatalf("scopeSet=%v audSet=%v, want both false", scopeSet, audSet)
		}
	})

	t.Run("JSON-like empty slice without flag → set", func(t *testing.T) {
		body := &adminv1.AcceptConsentBody{
			GrantScope:               []string{},
			GrantAccessTokenAudience: []string{},
		}
		scopeSet, audSet := acceptConsentPresence(body)
		if !scopeSet || !audSet {
			t.Fatalf("scopeSet=%v audSet=%v, want both true (REST empty array)", scopeSet, audSet)
		}
	})

	t.Run("gRPC empty needs flag", func(t *testing.T) {
		// Wire-empty repeated arrives as nil; only the flag expresses deny-all.
		body := &adminv1.AcceptConsentBody{
			GrantScopeSet:               true,
			GrantAccessTokenAudienceSet: true,
		}
		scopeSet, audSet := acceptConsentPresence(body)
		if !scopeSet || !audSet {
			t.Fatalf("scopeSet=%v audSet=%v, want both true", scopeSet, audSet)
		}
		in := oauth2.AcceptConsentInput{
			GrantScope:       body.GetGrantScope(),
			GrantScopeSet:    scopeSet,
			GrantAudience:    body.GetGrantAccessTokenAudience(),
			GrantAudienceSet: audSet,
		}
		if !in.GrantScopeSet || len(in.GrantScope) != 0 {
			t.Fatalf("input scopes set=%v len=%d", in.GrantScopeSet, len(in.GrantScope))
		}
	})

	t.Run("non-empty list without flag still set via slice", func(t *testing.T) {
		body := &adminv1.AcceptConsentBody{GrantScope: []string{"openid"}}
		scopeSet, _ := acceptConsentPresence(body)
		if !scopeSet {
			t.Fatal("non-empty grant_scope must set presence")
		}
	})
}
