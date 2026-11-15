package di

import (
	"log/slog"
	"net/http"

	"github.com/google/wire"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/config"
	"github.com/granto-io/granto/consent/internal/csrf"
	"github.com/granto-io/granto/consent/internal/engine"
	"github.com/granto-io/granto/consent/internal/identityclient"
	"github.com/granto-io/granto/consent/internal/transport/public"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

// EngineSet provides the CSRF service, engine, and public HTTP router.
var EngineSet = wire.NewSet(
	provideCSRF,
	provideEngine,
	provideRouter,
)

func provideCSRF(cfg *config.Config) *csrf.Service {
	return csrf.New(cfg.CSRF.Secret)
}

func provideEngine(
	cfg *config.Config,
	logger *slog.Logger,
	admin adminclient.Client,
	identity *identityclient.Client,
	csrfSvc *csrf.Service,
) (*engine.Engine, error) {
	return engine.New(engine.Options{
		Logger:       logger,
		Admin:        admin,
		CSRF:         csrfSvc,
		Identity:     identity,
		Plugins:      pluginapi.Default(),
		Enabled:      cfg.Plugins.Enabled,
		PluginConfig: cfg.Plugins.Config,
	})
}

func provideRouter(eng *engine.Engine, logger *slog.Logger) (http.Handler, error) {
	return public.NewRouter(eng, public.Options{Logger: logger})
}
