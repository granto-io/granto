package app

import (
	"log/slog"
	"net/http"
)

// App holds process-level dependencies constructed by the DI graph.
// Lifecycle (ListenAndServe, shutdown) stays outside the Wire package.
type App struct {
	Logger *slog.Logger
	Public http.Handler
}

// NewApp assembles App from already-constructed dependencies.
func NewApp(logger *slog.Logger, public http.Handler) *App {
	return &App{
		Logger: logger,
		Public: public,
	}
}
