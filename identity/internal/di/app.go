package di

import (
	"github.com/google/wire"

	"github.com/granto-io/granto/identity/internal/app"
)

// AppSet is the full identity application graph.
var AppSet = wire.NewSet(
	ConfigSet,
	LoggerSet,
	PostgresSet,
	IdentitySet,
	app.NewApp,
)
