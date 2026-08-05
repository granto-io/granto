//go:build wireinject

package di

import (
	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/app"
)

// InitializeApp builds the core application graph.
func InitializeApp() (*app.App, error) {
	wire.Build(AppSet)
	return nil, nil
}
