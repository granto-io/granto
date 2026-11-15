//go:build wireinject

package di

import (
	"github.com/google/wire"

	"github.com/granto-io/granto/identity/internal/app"
)

// InitializeApp builds the identity application graph.
// configPath is resolved at the process edge (CLI flag / env), not inside providers.
func InitializeApp(configPath ConfigPath) (*app.App, error) {
	wire.Build(AppSet)
	return nil, nil
}
