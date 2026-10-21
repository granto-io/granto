package public

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

// OAuth 2.0 public endpoints (RFC 6749, 7009, 7662).

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	if v := q.Get(domain.FlowVerifierKindLogin.QueryParam()); v != "" {
		h.completeVerifier(w, r, domain.FlowVerifierKindLogin, v)
		return
	}
	if v := q.Get(domain.FlowVerifierKindConsent.QueryParam()); v != "" {
		h.completeVerifier(w, r, domain.FlowVerifierKindConsent, v)
		return
	}

	if h.flow == nil {
		h.notImplemented(w, r, "authorization")
		return
	}

	in := oauth2.AuthorizeInput{
		ClientID:            q.Get("client_id"),
		ResponseType:        q.Get("response_type"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		LoginHint:           q.Get("login_hint"),
		ACRValues:           q.Get("acr_values"),
		UILocales:           q.Get("ui_locales"),
		Display:             q.Get("display"),
		RequestURL:          requestURL(r),
	}
	if c, err := r.Cookie(oauth2.SessionCookieName); err == nil {
		in.ExistingSessionID = c.Value
	}

	result, err := h.flow.Authorize(r.Context(), in)
	if err != nil {
		h.writeAuthorizeError(w, err)
		return
	}
	http.Redirect(w, r, result.RedirectTo, http.StatusFound)
}

func (h *Handler) completeVerifier(w http.ResponseWriter, r *http.Request, kind domain.FlowVerifierKind, id string) {
	if h.flow == nil {
		h.notImplemented(w, r, "authorization")
		return
	}
	res, err := h.flow.CompleteVerifier(r.Context(), kind, id)
	if err != nil {
		h.writeAuthorizeError(w, err)
		return
	}
	h.setSessionCookie(w, res)
	http.Redirect(w, r, res.RedirectTo, http.StatusFound)
}

func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = r.URL.Path
		if r.URL.RawQuery != "" {
			path += "?" + r.URL.RawQuery
		}
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return scheme + "://" + host + path
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "token")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	clientID, clientSecret := r.FormValue("client_id"), r.FormValue("client_secret")
	if id, secret, ok := parseBasicAuth(r.Header.Get("Authorization")); ok {
		clientID, clientSecret = id, secret
	}

	grantType := r.FormValue("grant_type")
	var (
		resp *oauth2.TokenResponse
		err  error
	)
	switch grantType {
	case "authorization_code":
		resp, err = h.flow.ExchangeCode(r.Context(), oauth2.ExchangeCodeInput{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			CodeVerifier: r.FormValue("code_verifier"),
		})
	case "refresh_token":
		resp, err = h.flow.RefreshToken(r.Context(), oauth2.RefreshTokenInput{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RefreshToken: r.FormValue("refresh_token"),
			Scope:        r.FormValue("scope"),
		})
	case "client_credentials":
		resp, err = h.flow.ClientCredentials(r.Context(), oauth2.ClientCredentialsInput{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        r.FormValue("scope"),
		})
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		return
	}
	if err != nil {
		h.writeTokenError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) writeTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oauth2.ErrInvalidClient),
		errors.Is(err, oauth2.ErrInvalidClientSecret):
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
	case errors.Is(err, oauth2.ErrUnauthorizedClient):
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", err.Error())
	case errors.Is(err, oauth2.ErrInvalidGrant),
		errors.Is(err, oauth2.ErrInvalidCodeVerifier),
		errors.Is(err, oauth2.ErrSessionExpired),
		errors.Is(err, oauth2.ErrTokenNotFound):
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
	case errors.Is(err, oauth2.ErrInvalidScope):
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
	case errors.Is(err, oauth2.ErrPKCERequired),
		errors.Is(err, oauth2.ErrInvalidRequest):
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		h.logger.Error("token error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

func parseBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "revocation")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	clientID, clientSecret := r.FormValue("client_id"), r.FormValue("client_secret")
	if id, secret, ok := parseBasicAuth(r.Header.Get("Authorization")); ok {
		clientID, clientSecret = id, secret
	}
	err := h.flow.Revoke(r.Context(), oauth2.RevokeInput{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
	})
	if err != nil {
		h.writeTokenError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "introspection")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	clientID, clientSecret := r.FormValue("client_id"), r.FormValue("client_secret")
	if id, secret, ok := parseBasicAuth(r.Header.Get("Authorization")); ok {
		clientID, clientSecret = id, secret
	}
	resp, err := h.flow.Introspect(r.Context(), oauth2.IntrospectInput{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
	})
	if err != nil {
		h.writeTokenError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
