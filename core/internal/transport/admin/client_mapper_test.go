package admin

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
)

func TestParseClientType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw     string
		want    domain.ClientType
		wantErr bool
	}{
		{"confidential", domain.ClientTypeConfidential, false},
		{"public", domain.ClientTypePublic, false},
		{"trusted", domain.ClientTypeTrusted, false},
		{"", "", true},
		{"unknown", "", true},
	}
	for _, tc := range cases {
		got, err := parseClientType(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseClientType(%q): want error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseClientType(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("parseClientType(%q): got %q", tc.raw, got)
		}
	}
}

func TestApplyClientCreateDefaults(t *testing.T) {
	t.Parallel()

	t.Run("confidential defaults", func(t *testing.T) {
		c := &domain.Client{}
		applyClientCreateDefaults(c)
		if c.ClientType != domain.ClientTypeConfidential {
			t.Fatalf("client_type: %q", c.ClientType)
		}
		if c.TokenEndpointAuthMethod != domain.TokenEndpointAuthClientSecretBasic {
			t.Fatalf("auth method: %q", c.TokenEndpointAuthMethod)
		}
		if c.SubjectType != domain.SubjectTypePublic {
			t.Fatalf("subject: %q", c.SubjectType)
		}
		if len(c.Protocols) != 2 || c.Protocols[0] != "oauth2" || c.Protocols[1] != "oidc" {
			t.Fatalf("protocols: %#v", c.Protocols)
		}
		if c.IDTokenSignedAlg != "RS256" || c.UserinfoSignedAlg != "none" {
			t.Fatalf("algs: id=%q userinfo=%q", c.IDTokenSignedAlg, c.UserinfoSignedAlg)
		}
	})

	t.Run("public auth none", func(t *testing.T) {
		c := &domain.Client{ClientType: domain.ClientTypePublic}
		applyClientCreateDefaults(c)
		if c.TokenEndpointAuthMethod != domain.TokenEndpointAuthNone {
			t.Fatalf("auth method: %q", c.TokenEndpointAuthMethod)
		}
	})

	t.Run("preserves explicit values", func(t *testing.T) {
		c := &domain.Client{
			ClientType:              domain.ClientTypeTrusted,
			TokenEndpointAuthMethod: domain.TokenEndpointAuthPrivateKeyJWT,
			SubjectType:             domain.SubjectTypePairwise,
			Protocols:               []string{"gnap"},
			IDTokenSignedAlg:        "ES256",
			UserinfoSignedAlg:       "RS256",
		}
		applyClientCreateDefaults(c)
		if c.TokenEndpointAuthMethod != domain.TokenEndpointAuthPrivateKeyJWT {
			t.Fatal("auth method overwritten")
		}
		if c.Protocols[0] != "gnap" {
			t.Fatal("protocols overwritten")
		}
	})
}

func TestApplyClientBody(t *testing.T) {
	t.Parallel()

	meta, err := structpb.NewStruct(map[string]any{"team": "platform"})
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := structpb.NewStruct(map[string]any{"keys": []any{}})
	if err != nil {
		t.Fatal(err)
	}

	req := &adminv1.CreateClientRequest{
		Name:                              "App",
		Description:                       "desc",
		ClientType:                        "public",
		GrantTypes:                        []string{"authorization_code"},
		ResponseTypes:                     []string{"code"},
		RedirectUris:                      []string{"https://app/cb"},
		AllowedCorsOrigins:                []string{"https://app"},
		AllowedScopes:                     []string{"openid"},
		DefaultScopes:                     []string{"openid"},
		Audience:                          []string{"api"},
		TokenEndpointAuthMethod:           "none",
		TokenEndpointAuthSigningAlg:       "RS256",
		RequirePkce:                       true,
		SubjectType:                       "pairwise",
		SectorIdentifierUri:               "https://sector",
		IdTokenSignedAlg:                  "ES256",
		UserinfoSignedAlg:                 "RS256",
		PostLogoutUris:                    []string{"https://app/logout"},
		FrontchannelLogoutUri:             "https://app/fc",
		FrontchannelLogoutSessionRequired: true,
		BackchannelLogoutUri:              "https://app/bc",
		BackchannelLogoutSessionRequired:  true,
		AccessTokenTtlSeconds:             3600,
		RefreshTokenTtlSeconds:            7200,
		IdTokenTtlSeconds:                 1800,
		SkipConsent:                       true,
		LogoUri:                           "https://logo",
		ClientUri:                         "https://app",
		PolicyUri:                         "https://policy",
		TosUri:                            "https://tos",
		Contacts:                          []string{"a@b.c"},
		Metadata:                          meta,
		Protocols:                         []string{"oauth2"},
		JwksUri:                           "https://jwks",
		Jwks:                              jwks,
	}

	c := &domain.Client{
		Name:                    "old",
		ClientType:              domain.ClientTypeConfidential,
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
		SubjectType:             domain.SubjectTypePublic,
		IDTokenSignedAlg:        "RS256",
		UserinfoSignedAlg:       "none",
		Protocols:               []string{"oidc"},
	}
	if err := applyClientBody(c, req); err != nil {
		t.Fatal(err)
	}

	if c.Name != "App" || c.Description != "desc" {
		t.Fatalf("name/desc: %q %q", c.Name, c.Description)
	}
	if c.ClientType != domain.ClientTypePublic {
		t.Fatalf("type: %q", c.ClientType)
	}
	if !c.HasGrantType(domain.GrantTypeAuthorizationCode) {
		t.Fatal("grant types")
	}
	if !c.RequirePKCE || !c.SkipConsent {
		t.Fatal("bools")
	}
	if c.AccessTokenTTL == nil || *c.AccessTokenTTL != time.Hour {
		t.Fatalf("access ttl: %v", c.AccessTokenTTL)
	}
	if c.Metadata["team"] != "platform" {
		t.Fatalf("metadata: %#v", c.Metadata)
	}
	if c.JWKS == nil {
		t.Fatal("jwks nil")
	}
	if c.Protocols[0] != "oauth2" {
		t.Fatalf("protocols: %#v", c.Protocols)
	}
}

func TestApplyClientBody_EmptyNamePreserves(t *testing.T) {
	t.Parallel()
	c := &domain.Client{Name: "keep"}
	if err := applyClientBody(c, &adminv1.UpdateClientRequest{}); err != nil {
		t.Fatal(err)
	}
	if c.Name != "keep" {
		t.Fatalf("got %q", c.Name)
	}
}

func TestApplyClientBody_InvalidType(t *testing.T) {
	t.Parallel()
	err := applyClientBody(&domain.Client{}, &adminv1.CreateClientRequest{
		Name:       "x",
		ClientType: "nope",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClientToProtoRoundTripBasics(t *testing.T) {
	t.Parallel()
	ttl := time.Hour
	now := time.Now().UTC().Truncate(time.Second)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	c := &domain.Client{
		ID:                      id,
		TenantID:                domain.DefaultTenantID,
		ClientID:                "my-client",
		Name:                    "N",
		ClientType:              domain.ClientTypeConfidential,
		GrantTypes:              []domain.GrantType{domain.GrantTypeRefreshToken},
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretBasic,
		SubjectType:             domain.SubjectTypePublic,
		AccessTokenTTL:          &ttl,
		IsDynamic:               true,
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	p := clientToProto(c)
	if p.Id != id.String() || p.ClientId != "my-client" || p.Name != "N" {
		t.Fatalf("basic fields: %#v", p)
	}
	if p.AccessTokenTtlSeconds != 3600 {
		t.Fatalf("ttl seconds: %d", p.AccessTokenTtlSeconds)
	}
	if !p.IsDynamic {
		t.Fatal("is_dynamic")
	}
	if p.CreatedAt.AsTime() != now || p.UpdatedAt.AsTime() != now {
		t.Fatal("timestamps")
	}
}

func TestTenantIDFromStr(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	if got := tenantIDFromStr(id.String()); got != id {
		t.Fatalf("got %v", got)
	}
	if got := tenantIDFromStr("bad"); got != domain.DefaultTenantID {
		t.Fatalf("fallback: %v", got)
	}
	if got := tenantIDFromStr(""); got != domain.DefaultTenantID {
		t.Fatalf("empty: %v", got)
	}
}

func TestDurationSecondsHelpers(t *testing.T) {
	t.Parallel()
	if durationToSeconds(nil) != 0 {
		t.Fatal("nil duration")
	}
	d := 90 * time.Second
	if durationToSeconds(&d) != 90 {
		t.Fatal("seconds")
	}
	if secondsToDuration(0) != nil {
		t.Fatal("zero seconds")
	}
	got := secondsToDuration(45)
	if got == nil || *got != 45*time.Second {
		t.Fatalf("got %v", got)
	}
}

func TestStructpbMapHelpers(t *testing.T) {
	t.Parallel()
	if mapToStructpb(nil) != nil || mapToStructpb(map[string]any{}) != nil {
		t.Fatal("empty map should be nil struct")
	}
	s := mapToStructpb(map[string]any{"k": "v"})
	if s == nil || s.AsMap()["k"] != "v" {
		t.Fatalf("got %#v", s)
	}
	if structpbToMap(nil) != nil {
		t.Fatal("nil struct")
	}
	if m := structpbToMap(s); m["k"] != "v" {
		t.Fatalf("got %#v", m)
	}
}

func TestGrantTypeStringHelpers(t *testing.T) {
	t.Parallel()
	gs := []domain.GrantType{domain.GrantTypeAuthorizationCode, domain.GrantTypeClientCredentials}
	ss := grantTypesToStrings(gs)
	if len(ss) != 2 || ss[0] != "authorization_code" {
		t.Fatalf("%#v", ss)
	}
	back := stringsToGrantTypes(ss)
	if back[1] != domain.GrantTypeClientCredentials {
		t.Fatalf("%#v", back)
	}
}
