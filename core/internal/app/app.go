package app

import (
	"log/slog"
	"net/http"

	"github.com/granto-io/granto/core/internal/repository"
)

// App holds process-level dependencies constructed by the DI graph.
// Lifecycle (ListenAndServe, shutdown) stays outside the Wire package.
type App struct {
	Logger  *slog.Logger
	Public  http.Handler
	Clients repository.ClientRepository
}

// NewApp assembles App from already-constructed dependencies.
func NewApp(
	logger *slog.Logger,
	public http.Handler,
	clients repository.ClientRepository,
) *App {
	return &App{
		Logger:  logger,
		Public:  public,
		Clients: clients,
	}
}
