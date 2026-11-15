package public

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/granto-io/granto/consent/internal/engine"
)

// Options configures the consent router.
type Options struct {
	Logger *slog.Logger

	// Middlewares are applied after the built-in middleware and before
	// route handlers (outermost first).
	Middlewares []Middleware
}

// NewRouter builds the chi router for the consent service's own HTTP
// surface: login and consent pages, including plugin sub-routes.
//
// The process health probe is registered separately by pkg/server, not here
// (see core/internal/app for the same split between protocol router and
// app-level health).
func NewRouter(eng *engine.Engine, opts Options) (http.Handler, error) {
	if eng == nil {
		return nil, fmt.Errorf("public: engine is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	r := chi.NewRouter()

	r.Use(recoverer(logger))
	r.Use(requestLogger(logger))

	for _, mw := range opts.Middlewares {
		if mw != nil {
			r.Use(mw)
		}
	}

	var routeErr error
	r.Group(func(gr chi.Router) {
		gr.Use(noCache)
		gr.Use(htmlSecurityHeaders)
		routeErr = eng.RegisterRoutes(gr)
	})
	if routeErr != nil {
		return nil, routeErr
	}

	return r, nil
}
