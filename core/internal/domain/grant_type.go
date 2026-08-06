package domain

// GrantType is an OAuth 2.0 grant type identifier (IANA registry).
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
	GrantTypeJWTBearer         GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)
