package public

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/granto-io/granto/core/internal/oauth2"
)

// Confirm page for logout_scope=device|subject: GET must not end sessions
// (SameSite=Lax still sends cookies on top-level cross-site GET). POST from
// this same-origin form completes logout; cross-site POST does not get Lax cookies.
var logoutConfirmTmpl = template.Must(template.New("logout_confirm").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm logout</title>
</head>
<body>
<p>Confirm sign-out. This ends sessions on this device or for this account (including refresh tokens).</p>
<form method="post" action="/oauth2/logout">
{{ if .IDTokenHint }}<input type="hidden" name="id_token_hint" value="{{ .IDTokenHint }}">{{ end }}
{{ if .ClientID }}<input type="hidden" name="client_id" value="{{ .ClientID }}">{{ end }}
{{ if .PostLogoutRedirect }}<input type="hidden" name="post_logout_redirect_uri" value="{{ .PostLogoutRedirect }}">{{ end }}
{{ if .State }}<input type="hidden" name="state" value="{{ .State }}">{{ end }}
<button type="submit">Sign out</button>
</form>
</body>
</html>`))

type logoutConfirmView struct {
	IDTokenHint        string
	ClientID           string
	PostLogoutRedirect string
	State              string
}

func writeLogoutConfirmPage(w http.ResponseWriter, v logoutConfirmView) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	return logoutConfirmTmpl.Execute(w, v)
}

func secFetchSite(r *http.Request) string {
	return strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
}

// logoutGETNeedsConfirm decides whether GET must show the confirm form.
// B2: always for device|subject. E: Sec-Fetch-Site=cross-site → warn log; for
// session scope also confirm when there is no id_token_hint (cookie-only CSRF).
// Cross-site GET *with* id_token_hint stays allowed for session (typical RP redirect).
func (h *Handler) logoutGETNeedsConfirm(r *http.Request, in oauth2.LogoutInput) bool {
	site := secFetchSite(r)
	crossSite := site == "cross-site"
	if crossSite {
		h.logger.WarnContext(r.Context(), "logout GET Sec-Fetch-Site=cross-site",
			"sec_fetch_site", site,
			"has_id_token_hint", in.IDTokenHint != "",
			"logout_requires_confirm", h.flow != nil && h.flow.LogoutRequiresConfirm(),
		)
	}
	if h.flow != nil && h.flow.LogoutRequiresConfirm() {
		return true
	}
	// Harden session: cookie-only cross-site navigation.
	if crossSite && in.IDTokenHint == "" {
		return true
	}
	return false
}
