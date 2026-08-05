package public

import "net/http"

// GNAP public endpoints (RFC 9635).

// handleGNAPGrant starts a grant request (RFC 9635 §2).
func (h *Handler) handleGNAPGrant(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-grant")
}

// handleGNAPDiscovery returns AS capability hints (RFC 9635 §9, OPTIONS).
func (h *Handler) handleGNAPDiscovery(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-discovery")
}

// handleGNAPContinuePOST continues a grant — after interaction (§5.1) or polling (§5.2).
func (h *Handler) handleGNAPContinuePOST(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-continue")
}

// handleGNAPContinuePATCH modifies an ongoing grant request (RFC 9635 §5.3).
func (h *Handler) handleGNAPContinuePATCH(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-continue-modify")
}

// handleGNAPContinueDELETE cancels an ongoing grant request (RFC 9635 §5.4).
func (h *Handler) handleGNAPContinueDELETE(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-continue-revoke")
}

// handleGNAPTokenRotate rotates an access token (RFC 9635 §6.1).
func (h *Handler) handleGNAPTokenRotate(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-token-rotate")
}

// handleGNAPTokenRevoke revokes an access token via management URI (RFC 9635 §6.2 / DELETE).
func (h *Handler) handleGNAPTokenRevoke(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-token-revoke")
}

// handleGNAPInteract is the AS-hosted redirect interaction page (RFC 9635 §4.1.1).
// Eventually this may hand off to the consent module; stub stays on core for now.
func (h *Handler) handleGNAPInteract(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-interact")
}

// handleGNAPDevice is the static user_code entry URI (RFC 9635 §4.1.2).
func (h *Handler) handleGNAPDevice(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, r, "gnap-device")
}
