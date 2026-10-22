package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
)

func TestParseClientType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		want    domain.ClientType
		wantErr bool
	}{
		{name: "confidential", raw: "confidential", want: domain.ClientTypeConfidential},
		{name: "public", raw: "public", want: domain.ClientTypePublic},
		{name: "trusted", raw: "trusted", want: domain.ClientTypeTrusted},
		{name: "empty string", raw: "", wantErr: true},
		{name: "unknown value", raw: "unknown", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseClientType(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseClientType(%q) = %q, %v; want error", tc.raw, got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseClientType(%q) unexpected error: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("parseClientType(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestApplyClientCreateDefaults(t *testing.T) {
	t.Parallel()

	t.Run("empty client gets confidential defaults", func(t *testing.T) {
		c := &domain.Client{}
		applyClientCreateDefaults(c)
		if c.ClientType != domain.ClientTypeConfidential {
			t.Fatalf("ClientType = %q, want %q", c.ClientType, domain.ClientTypeConfidential)
		}
		if c.TokenEndpointAuthMethod != domain.TokenEndpointAuthClientSecretBasic {
			t.Fatalf("TokenEndpointAuthMethod = %q, want %q", c.TokenEndpointAuthMethod, domain.TokenEndpointAuthClientSecretBasic)
		}
		if c.SubjectType != domain.SubjectTypePublic {
			t.Fatalf("SubjectType = %q, want %q", c.SubjectType, domain.SubjectTypePublic)
		}
		wantProtocols := []string{"oauth2", "oidc"}
		if fmt.Sprint(c.Protocols) != fmt.Sprint(wantProtocols) {
			t.Fatalf("Protocols = %#v, want %#v", c.Protocols, wantProtocols)
		}
		if c.IDTokenSignedAlg != "RS256" {
			t.Fatalf("IDTokenSignedAlg = %q, want %q", c.IDTokenSignedAlg, "RS256")
		}
		if c.UserinfoSignedAlg != "none" {
			t.Fatalf("UserinfoSignedAlg = %q, want %q", c.UserinfoSignedAlg, "none")
		}
	})

	t.Run("public client defaults auth method to none", func(t *testing.T) {
		c := &domain.Client{ClientType: domain.ClientTypePublic}
		applyClientCreateDefaults(c)
		if c.TokenEndpointAuthMethod != domain.TokenEndpointAuthNone {
			t.Fatalf("TokenEndpointAuthMethod = %q, want %q", c.TokenEndpointAuthMethod, domain.TokenEndpointAuthNone)
		}
	})

	t.Run("explicit values are preserved", func(t *testing.T) {
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
			t.Fatalf("TokenEndpointAuthMethod overwritten: got %q, want %q", c.TokenEndpointAuthMethod, domain.TokenEndpointAuthPrivateKeyJWT)
		}
		if len(c.Protocols) != 1 || c.Protocols[0] != "gnap" {
			t.Fatalf("Protocols overwritten: got %#v, want [gnap]", c.Protocols)
		}
	})
}

func TestApplyClientBody(t *testing.T) {
	t.Parallel()

	meta, err := structpb.NewStruct(map[string]any{"team": "platform"})
	if err != nil {
		t.Fatalf("structpb.NewStruct(metadata): %v", err)
	}
	jwks, err := structpb.NewStruct(map[string]any{"keys": []any{}})
	if err != nil {
		t.Fatalf("structpb.NewStruct(jwks): %v", err)
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
		t.Fatalf("applyClientBody: unexpected error: %v", err)
	}

	if c.Name != "App" {
		t.Fatalf("Name = %q, want %q", c.Name, "App")
	}
	if c.Description != "desc" {
		t.Fatalf("Description = %q, want %q", c.Description, "desc")
	}
	if c.ClientType != domain.ClientTypePublic {
		t.Fatalf("ClientType = %q, want %q", c.ClientType, domain.ClientTypePublic)
	}
	if !c.HasGrantType(domain.GrantTypeAuthorizationCode) {
		t.Fatalf("HasGrantType(%q) = false, want true; GrantTypes=%v", domain.GrantTypeAuthorizationCode, c.GrantTypes)
	}
	if !c.RequirePKCE {
		t.Fatalf("RequirePKCE = false, want true")
	}
	if !c.SkipConsent {
		t.Fatalf("SkipConsent = false, want true")
	}
	if c.AccessTokenTTL == nil || *c.AccessTokenTTL != time.Hour {
		t.Fatalf("AccessTokenTTL = %v, want %v", c.AccessTokenTTL, time.Hour)
	}
	if c.Metadata["team"] != "platform" {
		t.Fatalf(`Metadata["team"] = %#v, want %q; Metadata=%#v`, c.Metadata["team"], "platform", c.Metadata)
	}
	if c.JWKS == nil {
		t.Fatalf("JWKS = nil, want non-nil map from request")
	}
	if len(c.Protocols) == 0 || c.Protocols[0] != "oauth2" {
		t.Fatalf("Protocols = %#v, want starting with %q", c.Protocols, "oauth2")
	}
}

func TestApplyClientBody_EmptyNamePreserves(t *testing.T) {
	t.Parallel()
	c := &domain.Client{Name: "keep"}
	if err := applyClientBody(c, &adminv1.UpdateClientRequest{}); err != nil {
		t.Fatalf("applyClientBody: unexpected error: %v", err)
	}
	if c.Name != "keep" {
		t.Fatalf("Name = %q, want %q (empty request name must not overwrite)", c.Name, "keep")
	}
}

func TestApplyClientBody_InvalidType(t *testing.T) {
	t.Parallel()
	err := applyClientBody(&domain.Client{}, &adminv1.CreateClientRequest{
		Name:       "x",
		ClientType: "nope",
	})
	if err == nil {
		t.Fatalf("applyClientBody(client_type=%q) = nil error, want validation error", "nope")
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
	if p.Id != id.String() {
		t.Fatalf("Id = %q, want %q", p.Id, id.String())
	}
	if p.ClientId != "my-client" {
		t.Fatalf("ClientId = %q, want %q", p.ClientId, "my-client")
	}
	if p.Name != "N" {
		t.Fatalf("Name = %q, want %q", p.Name, "N")
	}
	if p.AccessTokenTtlSeconds != 3600 {
		t.Fatalf("AccessTokenTtlSeconds = %d, want %d", p.AccessTokenTtlSeconds, 3600)
	}
	if !p.IsDynamic {
		t.Fatalf("IsDynamic = false, want true")
	}
	if p.CreatedAt.AsTime() != now {
		t.Fatalf("CreatedAt = %v, want %v", p.CreatedAt.AsTime(), now)
	}
	if p.UpdatedAt.AsTime() != now {
		t.Fatalf("UpdatedAt = %v, want %v", p.UpdatedAt.AsTime(), now)
	}
}

func TestResolveRequestTenant(t *testing.T) {
	t.Parallel()
	ctx := WithTenantID(context.Background(), domain.DefaultTenantID)

	t.Run("empty uses auth tenant", func(t *testing.T) {
		got, err := resolveRequestTenant(ctx, "")
		if err != nil {
			t.Fatalf("resolveRequestTenant: %v", err)
		}
		if got != domain.DefaultTenantID {
			t.Fatalf("got %v, want DefaultTenantID", got)
		}
	})
	t.Run("matching uuid ok", func(t *testing.T) {
		got, err := resolveRequestTenant(ctx, domain.DefaultTenantID.String())
		if err != nil {
			t.Fatalf("resolveRequestTenant: %v", err)
		}
		if got != domain.DefaultTenantID {
			t.Fatalf("got %v, want DefaultTenantID", got)
		}
	})
	t.Run("foreign tenant denied", func(t *testing.T) {
		_, err := resolveRequestTenant(ctx, uuid.New().String())
		assertStatusCode(t, err, codes.PermissionDenied)
	})
	t.Run("invalid uuid", func(t *testing.T) {
		_, err := resolveRequestTenant(ctx, "bad")
		assertStatusCode(t, err, codes.InvalidArgument)
	})
}

func TestDurationSecondsHelpers(t *testing.T) {
	t.Parallel()

	t.Run("nil duration to seconds is zero", func(t *testing.T) {
		if got := durationToSeconds(nil); got != 0 {
			t.Fatalf("durationToSeconds(nil) = %d, want 0", got)
		}
	})
	t.Run("duration to seconds", func(t *testing.T) {
		d := 90 * time.Second
		if got := durationToSeconds(&d); got != 90 {
			t.Fatalf("durationToSeconds(90s) = %d, want 90", got)
		}
	})
	t.Run("zero seconds to duration is nil", func(t *testing.T) {
		if got := secondsToDuration(0); got != nil {
			t.Fatalf("secondsToDuration(0) = %v, want nil", got)
		}
	})
	t.Run("seconds to duration", func(t *testing.T) {
		got := secondsToDuration(45)
		if got == nil {
			t.Fatalf("secondsToDuration(45) = nil, want 45s")
		}
		if *got != 45*time.Second {
			t.Fatalf("secondsToDuration(45) = %v, want 45s", *got)
		}
	})
}

func TestStructpbMapHelpers(t *testing.T) {
	t.Parallel()

	t.Run("empty maps become nil struct", func(t *testing.T) {
		if got := mapToStructpb(nil); got != nil {
			t.Fatalf("mapToStructpb(nil) = %#v, want nil", got)
		}
		if got := mapToStructpb(map[string]any{}); got != nil {
			t.Fatalf("mapToStructpb(empty) = %#v, want nil", got)
		}
	})
	t.Run("round-trip map", func(t *testing.T) {
		s := mapToStructpb(map[string]any{"k": "v"})
		if s == nil {
			t.Fatalf("mapToStructpb({k:v}) = nil, want struct")
		}
		if got := s.AsMap()["k"]; got != "v" {
			t.Fatalf(`AsMap()["k"] = %#v, want %q`, got, "v")
		}
		m := structpbToMap(s)
		if m["k"] != "v" {
			t.Fatalf(`structpbToMap(...)[ "k" ] = %#v, want %q`, m["k"], "v")
		}
	})
	t.Run("nil struct to map", func(t *testing.T) {
		if got := structpbToMap(nil); got != nil {
			t.Fatalf("structpbToMap(nil) = %#v, want nil", got)
		}
	})
}
