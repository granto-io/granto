package domain

// OIDCContext carries OpenID Connect authorize parameters for the login UI.
type OIDCContext struct {
	ACRValues         []string       `json:"acr_values,omitempty"`
	UILocales         []string       `json:"ui_locales,omitempty"`
	Display           string         `json:"display,omitempty"`
	LoginHint         string         `json:"login_hint,omitempty"`
	IDTokenHintClaims map[string]any `json:"id_token_hint_claims,omitempty"`
}
