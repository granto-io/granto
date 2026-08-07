package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/postgres"
	"github.com/granto-io/granto/core/internal/transport/admin"
)

// App holds process-level dependencies constructed by the DI graph.
// Lifecycle methods (Run) live here; Wire only builds the graph.
type App struct {
	Config *config.Config
	Logger *slog.Logger
	Public http.Handler
	DB     *postgres.DB
	Admin  *admin.Server

	publicHTTP *http.Server
}

// NewApp assembles App from already-constructed dependencies.
func NewApp(
	cfg *config.Config,
	logger *slog.Logger,
	public http.Handler,
	db *postgres.DB,
	adminSrv *admin.Server,
) *App {
	return &App{
		Config: cfg,
		Logger: logger,
		Public: public,
		DB:     db,
		Admin:  adminSrv,
	}
}

// Run starts public HTTP, admin gRPC, and admin REST gateway, then blocks until
// ctx is cancelled. Shutdown strategy: stop accepting new requests, drain
// in-flight work within Server.ShutdownTimeout, then close the DB pool.
func (a *App) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.Handle("/", a.Public)

	a.publicHTTP = &http.Server{
		Addr:              a.Config.Server.PublicAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		a.Logger.Info("public HTTP listening", "addr", a.Config.Server.PublicAddr)
		err := a.publicHTTP.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("public HTTP: %w", err)
		}
		return nil
	})

	// Bind gRPC before starting the gateway so dials do not race Listen.
	grpcLis, err := a.Admin.ListenGRPC(a.Config.Server.AdminGRPCAddr)
	if err != nil {
		return fmt.Errorf("admin gRPC: %w", err)
	}

	g.Go(func() error {
		a.Logger.Info("admin gRPC listening", "addr", a.Config.Server.AdminGRPCAddr)
		if err := a.Admin.ServeGRPC(grpcLis); err != nil {
			return fmt.Errorf("admin gRPC: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		a.Logger.Info("admin REST gateway listening", "addr", a.Config.Server.AdminRESTAddr)
		if err := a.Admin.RunGateway(gctx, a.Config.Server.AdminRESTAddr, a.Config.Server.AdminGRPCAddr); err != nil {
			return fmt.Errorf("admin gateway: %w", err)
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
			a.Logger.Error("public HTTP shutdown", "error", err)
			firstErr = err
		}
		if err := a.Admin.ShutdownHTTP(shutdownCtx); err != nil {
			a.Logger.Error("admin HTTP shutdown", "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		a.Admin.StopGRPC(shutdownCtx)

		if a.DB != nil {
			a.DB.Close()
			a.Logger.Info("postgres pool closed")
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
