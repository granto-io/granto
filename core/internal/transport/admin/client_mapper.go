package admin

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/netutil"
)

// clientBody is the shared writable surface of CreateClientRequest and UpdateClientRequest.
type clientBody interface {
	GetName() string
	GetDescription() string
	GetClientType() string
	GetGrantTypes() []string
	GetResponseTypes() []string
	GetRedirectUris() []string
	GetAllowedCorsOrigins() []string
	GetAllowedScopes() []string
	GetDefaultScopes() []string
	GetAudience() []string
	GetTokenEndpointAuthMethod() string
	GetTokenEndpointAuthSigningAlg() string
	GetRequirePkce() bool
	GetSubjectType() string
	GetSectorIdentifierUri() string
	GetIdTokenSignedAlg() string
	GetUserinfoSignedAlg() string
	GetPostLogoutUris() []string
	GetFrontchannelLogoutUri() string
	GetFrontchannelLogoutSessionRequired() bool
	GetBackchannelLogoutUri() string
	GetBackchannelLogoutSessionRequired() bool
	GetAccessTokenTtlSeconds() int32
	GetRefreshTokenTtlSeconds() int32
	GetIdTokenTtlSeconds() int32
	GetSkipConsent() bool
	GetLogoUri() string
	GetClientUri() string
	GetPolicyUri() string
	GetTosUri() string
	GetContacts() []string
	GetMetadata() *structpb.Struct
	GetProtocols() []string
	GetJwksUri() string
	GetJwks() *structpb.Struct
}

// applyClientBody copies mutable fields from an admin request onto c.
// Empty client_type / auth method / subject_type / signing algs leave existing values.
// Name is applied only when non-empty. Metadata and JWKS are applied when present in the request.
func applyClientBody(c *domain.Client, in clientBody) error {
	if name := in.GetName(); name != "" {
		c.Name = name
	}
	c.Description = in.GetDescription()

	if raw := in.GetClientType(); raw != "" {
		ct, err := parseClientType(raw)
		if err != nil {
			return err
		}
		c.ClientType = ct
	}

	c.GrantTypes = domain.GrantTypesFromStrings(in.GetGrantTypes())
	c.ResponseTypes = in.GetResponseTypes()
	c.RedirectURIs = in.GetRedirectUris()
	c.AllowedCORSOrigins = in.GetAllowedCorsOrigins()
	c.AllowedScopes = in.GetAllowedScopes()
	c.DefaultScopes = in.GetDefaultScopes()
	c.Audience = in.GetAudience()

	if raw := in.GetTokenEndpointAuthMethod(); raw != "" {
		c.TokenEndpointAuthMethod = domain.TokenEndpointAuthMethod(raw)
	}
	c.TokenEndpointAuthSigningAlg = in.GetTokenEndpointAuthSigningAlg()
	c.RequirePKCE = in.GetRequirePkce()

	if raw := in.GetSubjectType(); raw != "" {
		c.SubjectType = domain.SubjectType(raw)
	}
	c.SectorIdentifierURI = in.GetSectorIdentifierUri()
	if raw := in.GetIdTokenSignedAlg(); raw != "" {
		c.IDTokenSignedAlg = raw
	}
	if raw := in.GetUserinfoSignedAlg(); raw != "" {
		c.UserinfoSignedAlg = raw
	}

	c.PostLogoutURIs = in.GetPostLogoutUris()
	c.FrontChannelLogoutURI = strings.TrimSpace(in.GetFrontchannelLogoutUri())
	c.FrontChannelLogoutSessionRequired = in.GetFrontchannelLogoutSessionRequired()
	c.BackChannelLogoutURI = strings.TrimSpace(in.GetBackchannelLogoutUri())
	c.BackChannelLogoutSessionRequired = in.GetBackchannelLogoutSessionRequired()
	if err := validateLogoutChannelURI("frontchannel_logout_uri", c.FrontChannelLogoutURI); err != nil {
		return err
	}
	if err := validateLogoutChannelURI("backchannel_logout_uri", c.BackChannelLogoutURI); err != nil {
		return err
	}

	c.AccessTokenTTL = secondsToDuration(in.GetAccessTokenTtlSeconds())
	c.RefreshTokenTTL = secondsToDuration(in.GetRefreshTokenTtlSeconds())
	c.IDTokenTTL = secondsToDuration(in.GetIdTokenTtlSeconds())
	c.SkipConsent = in.GetSkipConsent()

	c.LogoURI = in.GetLogoUri()
	c.ClientURI = in.GetClientUri()
	c.PolicyURI = in.GetPolicyUri()
	c.TosURI = in.GetTosUri()
	c.Contacts = in.GetContacts()

	if in.GetMetadata() != nil {
		c.Metadata = structpbToMap(in.GetMetadata())
	}
	if protocols := in.GetProtocols(); len(protocols) > 0 {
		c.Protocols = protocols
	}
	c.JWKSURI = in.GetJwksUri()
	if in.GetJwks() != nil {
		c.JWKS = structpbToMap(in.GetJwks())
	}

	return nil
}

func applyClientCreateDefaults(c *domain.Client) {
	if c.ClientType == "" {
		c.ClientType = domain.ClientTypeConfidential
	}
	if c.TokenEndpointAuthMethod == "" {
		if c.ClientType == domain.ClientTypePublic {
			c.TokenEndpointAuthMethod = domain.TokenEndpointAuthNone
		} else {
			c.TokenEndpointAuthMethod = domain.TokenEndpointAuthClientSecretBasic
		}
	}
	if c.SubjectType == "" {
		c.SubjectType = domain.SubjectTypePublic
	}
	if len(c.Protocols) == 0 {
		c.Protocols = []string{"oauth2", "oidc"}
	}
	if c.IDTokenSignedAlg == "" {
		c.IDTokenSignedAlg = "RS256"
	}
	if c.UserinfoSignedAlg == "" {
		c.UserinfoSignedAlg = "none"
	}
}

func parseClientType(raw string) (domain.ClientType, error) {
	ct := domain.ClientType(raw)
	switch ct {
	case domain.ClientTypeConfidential, domain.ClientTypePublic, domain.ClientTypeTrusted:
		return ct, nil
	default:
		return "", fmt.Errorf("client_type must be confidential, public, or trusted")
	}
}

func clientToProto(c *domain.Client) *adminv1.Client {
	return &adminv1.Client{
		Id:                                c.ID.String(),
		TenantId:                          c.TenantID.String(),
		ClientId:                          c.ClientID,
		Name:                              c.Name,
		Description:                       c.Description,
		ClientType:                        string(c.ClientType),
		GrantTypes:                        domain.GrantTypesToStrings(c.GrantTypes),
		ResponseTypes:                     c.ResponseTypes,
		RedirectUris:                      c.RedirectURIs,
		AllowedCorsOrigins:                c.AllowedCORSOrigins,
		AllowedScopes:                     c.AllowedScopes,
		DefaultScopes:                     c.DefaultScopes,
		Audience:                          c.Audience,
		TokenEndpointAuthMethod:           string(c.TokenEndpointAuthMethod),
		TokenEndpointAuthSigningAlg:       c.TokenEndpointAuthSigningAlg,
		RequirePkce:                       c.RequirePKCE,
		SubjectType:                       string(c.SubjectType),
		SectorIdentifierUri:               c.SectorIdentifierURI,
		IdTokenSignedAlg:                  c.IDTokenSignedAlg,
		UserinfoSignedAlg:                 c.UserinfoSignedAlg,
		PostLogoutUris:                    c.PostLogoutURIs,
		FrontchannelLogoutUri:             c.FrontChannelLogoutURI,
		FrontchannelLogoutSessionRequired: c.FrontChannelLogoutSessionRequired,
		BackchannelLogoutUri:              c.BackChannelLogoutURI,
		BackchannelLogoutSessionRequired:  c.BackChannelLogoutSessionRequired,
		AccessTokenTtlSeconds:             durationToSeconds(c.AccessTokenTTL),
		RefreshTokenTtlSeconds:            durationToSeconds(c.RefreshTokenTTL),
		IdTokenTtlSeconds:                 durationToSeconds(c.IDTokenTTL),
		SkipConsent:                       c.SkipConsent,
		LogoUri:                           c.LogoURI,
		ClientUri:                         c.ClientURI,
		PolicyUri:                         c.PolicyURI,
		TosUri:                            c.TosURI,
		Contacts:                          c.Contacts,
		Metadata:                          mapToStructpb(c.Metadata),
		Protocols:                         c.Protocols,
		JwksUri:                           c.JWKSURI,
		Jwks:                              mapToStructpb(c.JWKS),
		IsDynamic:                         c.IsDynamic,
		CreatedAt:                         timestamppb.New(c.CreatedAt),
		UpdatedAt:                         timestamppb.New(c.UpdatedAt),
	}
}

func validateLogoutChannelURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	if err := netutil.ValidateOutboundURL(raw); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func durationToSeconds(d *time.Duration) int32 {
	if d == nil {
		return 0
	}
	return int32(d.Seconds())
}

func secondsToDuration(s int32) *time.Duration {
	if s == 0 {
		return nil
	}
	d := time.Duration(s) * time.Second
	return &d
}

func mapToStructpb(m map[string]any) *structpb.Struct {
	if len(m) == 0 {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}

func structpbToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}
