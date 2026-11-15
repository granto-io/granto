// Package app holds process-level dependencies constructed by the DI graph.
// Lifecycle methods (Run) live here; Wire only builds the graph.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/granto-io/granto/identity/internal/config"
	"github.com/granto-io/granto/identity/internal/postgres"
	"github.com/granto-io/granto/identity/internal/transport/identity"
)

// App holds process-level dependencies constructed by the DI graph.
type App struct {
	Config *config.Config
	Logger *slog.Logger
	DB     *postgres.DB
	Server *identity.Server
}

// NewApp assembles App from already-constructed dependencies.
func NewApp(
	cfg *config.Config,
	logger *slog.Logger,
	db *postgres.DB,
	srv *identity.Server,
) *App {
	return &App{
		Config: cfg,
		Logger: logger,
		DB:     db,
		Server: srv,
	}
}

// Run starts the identity gRPC server and REST gateway, then blocks until
// ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)

	// Bind gRPC before starting the gateway so dials do not race Listen.
	grpcLis, err := a.Server.ListenGRPC(a.Config.Server.GRPCAddr)
	if err != nil {
		return fmt.Errorf("identity gRPC: %w", err)
	}

	g.Go(func() error {
		a.Logger.Info("identity gRPC listening", "addr", a.Config.Server.GRPCAddr)
		if err := a.Server.ServeGRPC(grpcLis); err != nil {
			return fmt.Errorf("identity gRPC: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		a.Logger.Info("identity REST gateway listening", "addr", a.Config.Server.RESTAddr)
		if err := a.Server.RunGateway(gctx, a.Config.Server.RESTAddr, a.Config.Server.GRPCAddr); err != nil {
			return fmt.Errorf("identity gateway: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-gctx.Done()
		a.Logger.Info("shutting down", "timeout", a.Config.Server.ShutdownTimeout)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.Config.Server.ShutdownTimeout)
		defer cancel()

		var firstErr error
		if err := a.Server.ShutdownHTTP(shutdownCtx); err != nil {
			a.Logger.Error("identity HTTP shutdown", "error", err)
			firstErr = err
		}
		a.Server.StopGRPC(shutdownCtx)

		if a.DB != nil {
			a.DB.Close()
			a.Logger.Info("postgres pool closed")
		}

		return firstErr
	})

	return g.Wait()
}
