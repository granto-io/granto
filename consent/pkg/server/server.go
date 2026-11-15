// Package server is the embeddable entry point for granto-consent.
//
// A thin cmd/main.go in this repository wraps Run with the built-in
// plugins (see internal/plugins). Operators who need a custom plugin set
// write their own main.go that blank-imports Run's package alongside their
// plugin packages, without forking granto.
package server

import (
	"context"
	"fmt"

	"github.com/granto-io/granto/consent/internal/di"
)

// Run builds the consent application graph and serves the consent HTTP
// stack until ctx is cancelled.
func Run(ctx context.Context, configPath string) error {
	a, err := di.InitializeApp(di.ConfigPath(configPath))
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	if err := a.Run(ctx); err != nil {
		return fmt.Errorf("consent: %w", err)
	}
	return nil
}
