package di

import (
	"log/slog"
	"os"

	"github.com/google/wire"
)

// LoggerSet provides the process logger.
var LoggerSet = wire.NewSet(provideLogger)

func provideLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}
