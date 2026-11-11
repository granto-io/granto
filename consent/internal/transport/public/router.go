package public

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Options configures the consent router.
type Options struct {
	Logger *slog.Logger

	// Middlewares are applied after the built-in middleware and before
	// route handlers (outermost first).
	Middlewares []Middleware
}

// NewRouter builds the chi router for the consent service's own HTTP
// surface (login/consent pages). The process health probe is registered
// separately by pkg/server, not here (see core/internal/app for the same
// split between protocol router and app-level health).
func NewRouter(h *Handler, opts Options) http.Handler {
	logger := opts.Logger
	if logger == nil {
		if h != nil && h.logger != nil {
			logger = h.logger
		} else {
			logger = slog.Default()
		}
	}
	if h == nil {
		h = NewHandler(logger)
	}

	r := chi.NewRouter()

	r.Use(recoverer(logger))
	r.Use(requestLogger(logger))

	for _, mw := range opts.Middlewares {
		if mw != nil {
			r.Use(mw)
		}
	}

	r.Group(func(gr chi.Router) {
		gr.Use(noCache)
		gr.Get("/login", h.handleLoginGet)
		gr.Post("/login", h.handleLoginPost)
		gr.Get("/consent", h.handleConsentGet)
		gr.Post("/consent", h.handleConsentPost)
	})

	return r
}
