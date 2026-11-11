package public

import "net/http"

// handleConsentGet will render the consent page for the consent_challenge
// from core (fetched via AdminClient), showing the requested scopes/client.
// Stub for now.
func (h *Handler) handleConsentGet(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "GET /consent")
}

// handleConsentPost will accept or reject the consent challenge via core's
// AdminClient, based on the user's decision. Stub for now.
func (h *Handler) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "POST /consent")
}
