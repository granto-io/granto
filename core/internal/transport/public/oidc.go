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
	h.notImplemented(w, r, "logout")
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
