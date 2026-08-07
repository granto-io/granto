package di

import (
	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/app"
)

// AppSet is the full core application graph.
var AppSet = wire.NewSet(
	ConfigSet,
	LoggerSet,
	PublicHTTPSet,
	PostgresSet,
	RedisSet,
	AdminSet,
	app.NewApp,
)
