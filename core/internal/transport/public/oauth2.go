package public

import "net/http"

// OAuth 2.0 public endpoints (RFC 6749, 7009, 7662).

func (h *Handler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "authorization")
}

func (h *Handler) handleToken(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "token")
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "revocation")
}

func (h *Handler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "introspection")
}
