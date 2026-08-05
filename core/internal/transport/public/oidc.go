package public

import "net/http"

// OpenID Connect public endpoints (Discovery, JWKS, UserInfo, RP-Initiated Logout).

func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "openid-configuration")
}

func (h *Handler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "jwks")
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "logout")
}

func (h *Handler) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "userinfo")
}
