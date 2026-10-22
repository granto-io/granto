package domain

// OIDCContext carries OpenID Connect authorize parameters for the login UI.
type OIDCContext struct {
	ACRValues         []string       `json:"acr_values,omitempty"`
	UILocales         []string       `json:"ui_locales,omitempty"`
	Display           string         `json:"display,omitempty"`
	LoginHint         string         `json:"login_hint,omitempty"`
	IDTokenHintClaims map[string]any `json:"id_token_hint_claims,omitempty"`
	// Prompt is the space-split OIDC prompt parameter (none, login, consent, …).
	Prompt []string `json:"prompt,omitempty"`
	// MaxAgeSeconds is OIDC max_age when set (nil = omitted).
	MaxAgeSeconds *int64 `json:"max_age,omitempty"`
}
