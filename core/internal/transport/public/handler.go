package public

import (
	"log/slog"
	"net/http"
)

// Handler is the shared HTTP adapter for public RFC endpoints.
// Protocol-specific handlers live in oauth2.go, oidc.go, and gnap.go.
type Handler struct {
	logger *slog.Logger
}

// NewHandler constructs a Handler. logger must be non-nil (use slog.Default
// only as a last resort in tests).
func NewHandler(logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{logger: logger}
}

func (h *Handler) notImplemented(w http.ResponseWriter, r *http.Request, endpoint string) {
	h.logger.WarnContext(r.Context(), "public endpoint not implemented",
		"endpoint", endpoint,
		"method", r.Method,
		"path", r.URL.Path,
	)
	// OAuth uses temporarily_unavailable; GNAP registry has no direct
	// equivalent — use invalid_request with description for stubs.
	code := "temporarily_unavailable"
	if isGNAPPath(r.URL.Path) {
		code = "invalid_request"
	}
	writeProtocolError(w, r, http.StatusNotImplemented, code, "not implemented")
}
