// Package server is the embeddable entry point for granto-consent.
//
// A thin cmd/main.go in this repository wraps Run with the built-in
// plugins (see internal/plugins). Operators who need a custom plugin set
// write their own main.go that blank-imports Run's package alongside their
// plugin packages, without forking granto.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/granto-io/granto/consent/internal/config"
	"github.com/granto-io/granto/consent/internal/transport/public"
)

// Run loads configuration, builds the process logger, and serves the
// consent HTTP stack until ctx is cancelled.
func Run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg)

	h := public.NewHandler(logger)
	router := public.NewRouter(h, public.Options{Logger: logger})

	// /health is a process-level concern, not part of the public login/
	// consent surface — same split (and same path) as core/internal/app.
	mux := newMux(router)

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		logger.Info("consent HTTP listening", "addr", cfg.Server.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("consent HTTP: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-gctx.Done()
		logger.Info("shutting down", "timeout", cfg.Server.ShutdownTimeout)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("consent HTTP shutdown", "error", err)
			return fmt.Errorf("consent HTTP shutdown: %w", err)
		}
		return nil
	})

	return g.Wait()
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// newMux mounts the process health probe next to the protocol router.
func newMux(router http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.Handle("/", router)
	return mux
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Log.Format) == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
