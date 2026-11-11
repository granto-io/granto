package public

import "net/http"

// handleLoginGet will render the login page for the login_challenge from
// core (fetched via AdminClient) and the active plugins. Stub for now.
func (h *Handler) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "GET /login")
}

// handleLoginPost will hand submitted credentials to the chosen plugin and,
// on success, accept the login challenge via core's AdminClient. Stub for
// now.
func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "POST /login")
}
