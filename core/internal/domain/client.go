package domain

import (
	"slices"
	"time"

	"github.com/google/uuid"
)

type ClientType string
type SubjectType string
type TokenEndpointAuthMethod string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
	ClientTypeTrusted      ClientType = "trusted"

	SubjectTypePublic   SubjectType = "public"
	SubjectTypePairwise SubjectType = "pairwise"

	TokenEndpointAuthClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	TokenEndpointAuthClientSecretPost  TokenEndpointAuthMethod = "client_secret_post"
	TokenEndpointAuthClientSecretJWT   TokenEndpointAuthMethod = "client_secret_jwt"
	TokenEndpointAuthPrivateKeyJWT     TokenEndpointAuthMethod = "private_key_jwt"
	TokenEndpointAuthNone              TokenEndpointAuthMethod = "none"
)

// Client is an OAuth2 / OIDC / GNAP client registration.
type Client struct {
	ID       uuid.UUID
	TenantID uuid.UUID

	ClientID         string
	ClientSecretHash string
	Name             string
	Description      string
	ClientType       ClientType

	GrantTypes         []GrantType
	ResponseTypes      []string
	RedirectURIs       []string
	AllowedCORSOrigins []string
	AllowedScopes      []string
	DefaultScopes      []string
	Audience           []string

	TokenEndpointAuthMethod     TokenEndpointAuthMethod
	TokenEndpointAuthSigningAlg string
	RequirePKCE                 bool

	SubjectType         SubjectType
	SectorIdentifierURI string
	IDTokenSignedAlg    string
	UserinfoSignedAlg   string

	PostLogoutURIs                    []string
	FrontChannelLogoutURI             string
	FrontChannelLogoutSessionRequired bool
	BackChannelLogoutURI              string
	BackChannelLogoutSessionRequired  bool

	AccessTokenTTL  *time.Duration
	RefreshTokenTTL *time.Duration
	IDTokenTTL      *time.Duration

	SkipConsent bool

	LogoURI   string
	ClientURI string
	PolicyURI string
	TosURI    string
	Contacts  []string
	Metadata  map[string]any

	Protocols []string
	JWKS      map[string]any
	JWKSURI   string

	// Dynamic Client Registration (RFC 7591). Plain registration_access_token
	// is never stored — only its hash. registration_client_uri is derived at
	// response time, not persisted.
	RegistrationAccessTokenHash string
	IsDynamic                   bool

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func (c *Client) IsPublic() bool {
	return c.ClientType == ClientTypePublic
}

func (c *Client) IsTrustedClient() bool {
	return c.ClientType == ClientTypeTrusted
}

func (c *Client) HasGrantType(grantType GrantType) bool {
	return slices.Contains(c.GrantTypes, grantType)
}

func (c *Client) HasRedirectURI(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) HasPostLogoutURI(uri string) bool {
	return slices.Contains(c.PostLogoutURIs, uri)
}

func (c *Client) HasScope(scope string) bool {
	return slices.Contains(c.AllowedScopes, scope)
}
