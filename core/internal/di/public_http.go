package di

import (
	"log/slog"
	"net/http"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/transport/public"
)

// PublicHTTPSet provides the public OAuth2 / OIDC / GNAP HTTP stack.
var PublicHTTPSet = wire.NewSet(
	public.NewHandler,
	providePublicRouter,
)

func providePublicRouter(h *public.Handler, logger *slog.Logger) http.Handler {
	return public.NewRouter(h, public.Options{Logger: logger})
}
