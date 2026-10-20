package public

import "net/http"

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
	h.notImplemented(w, r, "userinfo")
}
