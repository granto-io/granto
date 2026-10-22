package domain

import "testing"

func TestClientTypeHelpers(t *testing.T) {
	t.Parallel()

	t.Run("public client", func(t *testing.T) {
		c := &Client{ClientType: ClientTypePublic}
		if !c.IsPublic() {
			t.Fatalf("IsPublic() = false, want true for ClientType=%q", c.ClientType)
		}
		if c.IsTrustedClient() {
			t.Fatalf("IsTrustedClient() = true, want false for ClientType=%q", c.ClientType)
		}
	})

	t.Run("trusted client", func(t *testing.T) {
		c := &Client{ClientType: ClientTypeTrusted}
		if !c.IsTrustedClient() {
			t.Fatalf("IsTrustedClient() = false, want true for ClientType=%q", c.ClientType)
		}
		if c.IsPublic() {
			t.Fatalf("IsPublic() = true, want false for ClientType=%q", c.ClientType)
		}
	})

	t.Run("confidential client", func(t *testing.T) {
		c := &Client{ClientType: ClientTypeConfidential}
		if c.IsPublic() {
			t.Fatalf("IsPublic() = true, want false for ClientType=%q", c.ClientType)
		}
		if c.IsTrustedClient() {
			t.Fatalf("IsTrustedClient() = true, want false for ClientType=%q", c.ClientType)
		}
	})
}

func TestHasGrantType(t *testing.T) {
	t.Parallel()
	c := &Client{GrantTypes: []GrantType{GrantTypeAuthorizationCode, GrantTypeRefreshToken}}

	if !c.HasGrantType(GrantTypeAuthorizationCode) {
		t.Fatalf("HasGrantType(%q) = false, want true; grants=%v", GrantTypeAuthorizationCode, c.GrantTypes)
	}
	if c.HasGrantType(GrantTypeClientCredentials) {
		t.Fatalf("HasGrantType(%q) = true, want false; grants=%v", GrantTypeClientCredentials, c.GrantTypes)
	}
	empty := &Client{}
	if empty.HasGrantType(GrantTypeAuthorizationCode) {
		t.Fatalf("HasGrantType(%q) = true on empty GrantTypes, want false", GrantTypeAuthorizationCode)
	}
}

func TestHasRedirectURI(t *testing.T) {
	t.Parallel()
	c := &Client{RedirectURIs: []string{"https://a/cb", "https://b/cb"}}

	if !c.HasRedirectURI("https://a/cb") {
		t.Fatalf("HasRedirectURI(%q) = false, want true; uris=%v", "https://a/cb", c.RedirectURIs)
	}
	if c.HasRedirectURI("https://other") {
		t.Fatalf("HasRedirectURI(%q) = true, want false; uris=%v", "https://other", c.RedirectURIs)
	}
}

func TestHasPostLogoutURI(t *testing.T) {
	t.Parallel()
	c := &Client{PostLogoutURIs: []string{"https://a/bye"}}
	if !c.HasPostLogoutURI("https://a/bye") {
		t.Fatal("HasPostLogoutURI want true")
	}
	if c.HasPostLogoutURI("https://evil") {
		t.Fatal("HasPostLogoutURI want false")
	}
}

func TestHasScope(t *testing.T) {
	t.Parallel()
	c := &Client{AllowedScopes: []string{"openid", "profile"}}

	if !c.HasScope("openid") {
		t.Fatalf("HasScope(%q) = false, want true; scopes=%v", "openid", c.AllowedScopes)
	}
	if c.HasScope("email") {
		t.Fatalf("HasScope(%q) = true, want false; scopes=%v", "email", c.AllowedScopes)
	}
}

func TestGrantTypeStringHelpers(t *testing.T) {
	t.Parallel()
	ss := []string{"authorization_code", "refresh_token"}
	gs := GrantTypesFromStrings(ss)
	if gs[0] != GrantTypeAuthorizationCode {
		t.Fatalf("GrantTypesFromStrings(...)[0] = %q, want %q", gs[0], GrantTypeAuthorizationCode)
	}
	back := GrantTypesToStrings(gs)
	if back[1] != "refresh_token" {
		t.Fatalf("GrantTypesToStrings(...)[1] = %q, want %q", back[1], "refresh_token")
	}
}
