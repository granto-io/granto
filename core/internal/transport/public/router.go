package public

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/granto-io/granto/core/internal/reqmeta"
)

// Middleware is the stdlib-compatible plugin form:
// func(http.Handler) http.Handler. Run logic before next.ServeHTTP and/or
// after it (post-processing).
type Middleware func(http.Handler) http.Handler

// Options configures the public router.
type Options struct {
	Logger *slog.Logger

	// Middlewares are applied after built-in middleware and before route
	// handlers (outermost first). Use for shared plugins that must also
	// work on the grpc-gateway mux.
	Middlewares []Middleware
}

// NewRouter builds the public chi router for RFC OAuth2 / OIDC / GNAP endpoints.
// See api/public/README.md for the planned surface and path conventions.
//
// GNAP paths below are Granto's concrete URIs for abstract RFC endpoints
// (grant endpoint, continuation API, token management, interaction).
//
// Returns http.Handler so the app can wrap it with otelhttp and mount it
// on http.Server alongside other muxes.
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
		h = NewHandler(logger, nil, nil, nil, nil)
	}

	r := chi.NewRouter()

	// Built-in pipeline (outer → inner).
	r.Use(recoverer(logger))
	r.Use(requestLogger(logger))
	r.Use(noCache)
	r.Use(reqmeta.Middleware)

	for _, mw := range opts.Middlewares {
		if mw != nil {
			r.Use(mw)
		}
	}

	// Discovery / keys (OIDC)
	r.Get("/.well-known/openid-configuration", h.handleDiscovery)
	r.Get("/.well-known/jwks.json", h.handleJWKS)

	// OAuth 2.0
	r.Get("/oauth2/auth", h.handleAuthorize)
	r.Post("/oauth2/token", h.handleToken)
	r.Post("/oauth2/revoke", h.handleRevoke)
	r.Post("/oauth2/introspect", h.handleIntrospect)

	// OIDC
	r.Get("/oauth2/logout", h.handleLogout)
	r.Post("/oauth2/logout", h.handleLogout) // form body params (OIDC)
	r.Get("/userinfo", h.handleUserinfo)
	r.Post("/userinfo", h.handleUserinfo)

	// OIDC Dynamic Client Registration (RFC 7591) — same flag as Discovery.
	if h.cfg != nil && h.cfg.OIDC.DynamicClientRegistration.Enabled {
		r.Post("/oauth2/register", h.handleRegisterCreate)
		r.Get("/oauth2/register/{clientID}", h.handleRegisterRead)
		r.Put("/oauth2/register/{clientID}", h.handleRegisterUpdate)
		r.Delete("/oauth2/register/{clientID}", h.handleRegisterDelete)
	}

	// GNAP — grant endpoint + OPTIONS discovery (RFC 9635 §2, §9)
	r.Post("/gnap", h.handleGNAPGrant)
	r.Options("/gnap", h.handleGNAPDiscovery)

	// GNAP — continuation API (RFC 9635 §5)
	// Stable URI pattern (RFC examples use /continue with continuation access token).
	r.Post("/gnap/continue", h.handleGNAPContinuePOST)
	r.Patch("/gnap/continue", h.handleGNAPContinuePATCH)
	r.Delete("/gnap/continue", h.handleGNAPContinueDELETE)
	// Unique-per-grant URI pattern (RFC examples use /continue/{id} or /tx/{id}).
	r.Route("/gnap/continue/{continueID}", func(cr chi.Router) {
		cr.Post("/", h.handleGNAPContinuePOST)
		cr.Patch("/", h.handleGNAPContinuePATCH)
		cr.Delete("/", h.handleGNAPContinueDELETE)
	})

	// GNAP — token management API (RFC 9635 §6); URI is issued per token.
	r.Post("/gnap/token/{tokenID}", h.handleGNAPTokenRotate)
	r.Delete("/gnap/token/{tokenID}", h.handleGNAPTokenRevoke)

	// GNAP — AS-hosted interaction (RFC 9635 §4.1); browser UX, may later
	// delegate to consent module.
	r.Get("/gnap/interact/{interactID}", h.handleGNAPInteract)
	r.Get("/gnap/device", h.handleGNAPDevice)

	return r
}

func isGNAPPath(path string) bool {
	return strings.HasPrefix(path, "/gnap")
}
