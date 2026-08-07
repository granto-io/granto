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

// GrantTypesToStrings converts grant types to plain strings (DB / proto).
func GrantTypesToStrings(gs []GrantType) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = string(g)
	}
	return out
}

// GrantTypesFromStrings parses plain strings into grant types (DB / proto).
func GrantTypesFromStrings(ss []string) []GrantType {
	out := make([]GrantType, len(ss))
	for i, s := range ss {
		out[i] = GrantType(s)
	}
	return out
}
