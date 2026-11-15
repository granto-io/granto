// Package app holds process-level dependencies constructed by the DI graph.
// Lifecycle methods (Run) live here; Wire only builds the graph.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/config"
	"github.com/granto-io/granto/consent/internal/identityclient"
)

// App holds process-level dependencies constructed by the DI graph.
type App struct {
	Config   *config.Config
	Logger   *slog.Logger
	Admin    adminclient.Client
	Identity *identityclient.Client
	Public   http.Handler

	publicHTTP *http.Server
}

// NewApp assembles App from already-constructed dependencies.
func NewApp(
	cfg *config.Config,
	logger *slog.Logger,
	admin adminclient.Client,
	identity *identityclient.Client,
	public http.Handler,
) *App {
	return &App{
		Config:   cfg,
		Logger:   logger,
		Admin:    admin,
		Identity: identity,
		Public:   public,
	}
}

// Run starts the consent HTTP server and blocks until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.Handle("/", a.Public)

	a.publicHTTP = &http.Server{
		Addr:              a.Config.Server.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		a.Logger.Info("consent HTTP listening", "addr", a.Config.Server.Addr)
		if err := a.publicHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("consent HTTP: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-gctx.Done()
		a.Logger.Info("shutting down", "timeout", a.Config.Server.ShutdownTimeout)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.Config.Server.ShutdownTimeout)
		defer cancel()

		var firstErr error
		if err := a.publicHTTP.Shutdown(shutdownCtx); err != nil {
			a.Logger.Error("consent HTTP shutdown", "error", err)
			firstErr = err
		}
		if a.Admin != nil {
			if err := a.Admin.Close(); err != nil {
				a.Logger.Warn("close admin client", "error", err)
			}
		}
		if a.Identity != nil {
			if err := a.Identity.Close(); err != nil {
				a.Logger.Warn("close identity client", "error", err)
			}
		}
		return firstErr
	})

	return g.Wait()
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
