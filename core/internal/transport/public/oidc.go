package public

import (
	"errors"
	"net/http"
	"strings"

	"github.com/granto-io/granto/core/internal/oauth2"
)

// OpenID Connect public endpoints (Discovery, JWKS, UserInfo, RP-Initiated Logout).

func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if h.discovery == nil {
		h.notImplemented(w, r, "openid-configuration")
		return
	}
	writeJSON(w, http.StatusOK, h.discovery.Document())
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if h.keyMgr == nil {
		h.notImplemented(w, r, "jwks")
		return
	}
	jwks, err := h.keyMgr.JWKS(r.Context())
	if err != nil {
		h.logger.ErrorContext(r.Context(), "jwks error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, jwks)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "logout")
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
			return
		}
	}
	q := r.URL.Query()
	form := r.Form
	get := func(name string) string {
		if v := strings.TrimSpace(q.Get(name)); v != "" {
			return v
		}
		if form != nil {
			return strings.TrimSpace(form.Get(name))
		}
		return ""
	}
	in := oauth2.LogoutInput{
		IDTokenHint:        get("id_token_hint"),
		ClientID:           get("client_id"),
		PostLogoutRedirect: get("post_logout_redirect_uri"),
		State:              get("state"),
	}
	if c, err := r.Cookie(oauth2.SessionCookieName); err == nil {
		in.SessionIDFromCookie = c.Value
	}
	if c, err := r.Cookie(oauth2.DeviceCookieName); err == nil {
		in.DeviceIDFromCookie = c.Value
	}
	res, err := h.flow.Logout(r.Context(), in)
	if err != nil {
		h.writeLogoutError(w, err)
		return
	}
	if res.ClearCookie {
		h.clearSessionCookie(w)
	}
	if len(res.FrontChannelLogoutURLs) > 0 {
		if err := writeFrontChannelLogoutPage(w, res.RedirectTo, res.FrontChannelLogoutURLs); err != nil {
			h.logger.ErrorContext(r.Context(), "front-channel logout page", "err", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		}
		return
	}
	if res.RedirectTo != "" {
		http.Redirect(w, r, res.RedirectTo, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Logged out"))
}

func (h *Handler) writeLogoutError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oauth2.ErrInvalidRequest):
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		h.logger.Error("logout error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

func (h *Handler) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "userinfo")
		return
	}
	token, err := accessTokenFromRequest(r)
	if err != nil {
		writeUserInfoAuthError(w, "invalid_request", err.Error())
		return
	}
	claims, err := h.flow.UserInfo(r.Context(), token)
	if err != nil {
		h.writeUserInfoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func accessTokenFromRequest(r *http.Request) (string, error) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			return "", errors.New("authorization scheme must be Bearer")
		}
		tok := strings.TrimSpace(auth[len(prefix):])
		if tok == "" {
			return "", errors.New("missing access token")
		}
		return tok, nil
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return "", errors.New("invalid form body")
		}
		if tok := strings.TrimSpace(r.FormValue("access_token")); tok != "" {
			return tok, nil
		}
	}
	return "", errors.New("missing access token")
}

func (h *Handler) writeUserInfoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oauth2.ErrInvalidToken):
		writeUserInfoAuthError(w, "invalid_token", "The access token is missing, invalid, or expired")
	case errors.Is(err, oauth2.ErrInsufficientScope):
		writeUserInfoAuthError(w, "insufficient_scope", "The access token does not have openid scope")
	default:
		h.logger.Error("userinfo error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

func writeUserInfoAuthError(w http.ResponseWriter, code, description string) {
	status := http.StatusUnauthorized
	if code == "insufficient_scope" {
		status = http.StatusForbidden
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+description+`"`)
	writeOAuthError(w, status, code, description)
}
