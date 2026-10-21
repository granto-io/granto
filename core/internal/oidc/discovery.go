package oidc

import (
	"fmt"
	"strings"

	"github.com/granto-io/granto/core/internal/config"
)

// DiscoveryDocument is OpenID Connect Discovery / RFC 8414 metadata.
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`

	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	ResponseModesSupported        []string `json:"response_modes_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	SubjectTypesSupported         []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues       []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported               []string `json:"claims_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ClaimsParameterSupported      bool     `json:"claims_parameter_supported"`
	RequestParameterSupported     bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported  bool     `json:"request_uri_parameter_supported"`
}

// Discovery builds the OpenID Provider metadata document.
type Discovery struct {
	cfg *config.Config
}

// NewDiscovery constructs a discovery document builder.
func NewDiscovery(cfg *config.Config) *Discovery {
	return &Discovery{cfg: cfg}
}

// Document returns the current discovery document.
func (d *Discovery) Document() *DiscoveryDocument {
	issuer := strings.TrimRight(d.cfg.Token.Issuer, "/")
	alg := d.cfg.Token.DefaultAlgorithm
	if alg == "" {
		alg = "RS256"
	}

	scopes := []string{"openid", "profile", "email", "phone", "address", "offline_access"}
	scopes = append(scopes, d.cfg.OIDC.ExtraScopes...)

	doc := &DiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth2/auth", issuer),
		TokenEndpoint:         fmt.Sprintf("%s/oauth2/token", issuer),
		JWKSURI:               fmt.Sprintf("%s/.well-known/jwks.json", issuer),
		UserinfoEndpoint:      fmt.Sprintf("%s/userinfo", issuer),
		IntrospectionEndpoint: fmt.Sprintf("%s/oauth2/introspect", issuer),
		RevocationEndpoint:    fmt.Sprintf("%s/oauth2/revoke", issuer),
		EndSessionEndpoint:    fmt.Sprintf("%s/oauth2/logout", issuer),

		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query"},

		GrantTypesSupported: []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},

		ScopesSupported: scopes,

		SubjectTypesSupported:   []string{"public"},
		IDTokenSigningAlgValues: []string{alg},

		TokenEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},

		ClaimsSupported: []string{
			"sub", "iss", "iat", "exp", "aud", "jti",
			"auth_time", "nonce", "sid",
			"name", "given_name", "family_name", "email", "email_verified",
		},

		CodeChallengeMethodsSupported: []string{"S256", "plain"},

		ClaimsParameterSupported:     false,
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}

	if d.cfg.OIDC.DynamicClientRegistration.Enabled {
		doc.RegistrationEndpoint = fmt.Sprintf("%s/oauth2/register", issuer)
	}

	return doc
}
