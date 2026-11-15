package di

import (
	"github.com/google/wire"

	"github.com/granto-io/granto/consent/internal/app"
)

// AppSet is the full consent application graph.
var AppSet = wire.NewSet(
	ConfigSet,
	LoggerSet,
	ClientSet,
	EngineSet,
	app.NewApp,
)
