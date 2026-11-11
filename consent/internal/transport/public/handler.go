package public

import (
	"log/slog"
	"net/http"
)

// Handler is the shared HTTP adapter for the consent surface.
type Handler struct {
	logger *slog.Logger
}

// NewHandler constructs a Handler.
func NewHandler(logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{logger: logger}
}

func (h *Handler) notImplemented(w http.ResponseWriter, r *http.Request, endpoint string) {
	h.logger.WarnContext(r.Context(), "consent endpoint not implemented",
		"endpoint", endpoint,
		"method", r.Method,
		"path", r.URL.Path,
	)
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
