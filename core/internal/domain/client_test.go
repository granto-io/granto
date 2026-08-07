package domain

import "testing"

func TestClientTypeHelpers(t *testing.T) {
	t.Parallel()
	public := &Client{ClientType: ClientTypePublic}
	trusted := &Client{ClientType: ClientTypeTrusted}
	confidential := &Client{ClientType: ClientTypeConfidential}

	if !public.IsPublic() || public.IsTrustedClient() {
		t.Fatal("public")
	}
	if !trusted.IsTrustedClient() || trusted.IsPublic() {
		t.Fatal("trusted")
	}
	if confidential.IsPublic() || confidential.IsTrustedClient() {
		t.Fatal("confidential")
	}
}

func TestHasGrantType(t *testing.T) {
	t.Parallel()
	c := &Client{GrantTypes: []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken}}
	if !c.HasGrantType(GrantTypeAuthorizationCode) {
		t.Fatal("miss hit")
	}
	if c.HasGrantType(GrantTypeClientCredentials) {
		t.Fatal("false positive")
	}
	if (&Client{}).HasGrantType(GrantTypeAuthorizationCode) {
		t.Fatal("empty")
	}
}

func TestHasRedirectURI(t *testing.T) {
	t.Parallel()
	c := &Client{RedirectURIs: []string{"https://a/cb", "https://b/cb"}}
	if !c.HasRedirectURI("https://a/cb") {
		t.Fatal("miss hit")
	}
	if c.HasRedirectURI("https://other") {
		t.Fatal("false positive")
	}
}

func TestHasScope(t *testing.T) {
	t.Parallel()
	c := &Client{AllowedScopes: []string{"openid", "profile"}}
	if !c.HasScope("openid") {
		t.Fatal("miss hit")
	}
	if c.HasScope("email") {
		t.Fatal("false positive")
	}
}
