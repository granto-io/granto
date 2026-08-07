package di

import (
	"fmt"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/config"
)

// ConfigPath is the path to a YAML config file.
// Empty means built-in defaults + GRANTO_* env only (see config.Load).
type ConfigPath string

// ConfigSet loads application configuration.
// ConfigPath is an injector parameter supplied by main (flag / env at process edge).
var ConfigSet = wire.NewSet(
	provideConfig,
)

func provideConfig(path ConfigPath) (*config.Config, error) {
	cfg, err := config.Load(string(path))
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}
