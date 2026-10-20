package di

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/wire"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/keys"
	"github.com/granto-io/granto/core/internal/oidc"
	"github.com/granto-io/granto/core/internal/repository"
	repopg "github.com/granto-io/granto/core/internal/repository/postgres"
)

// KeysSet provides AS signing keys, ID Token issuer, and OIDC discovery.
var KeysSet = wire.NewSet(
	repopg.NewSigningKeyRepository,
	wire.Bind(new(repository.SigningKeyRepository), new(*repopg.SigningKeyRepository)),
	provideKeyManager,
	oidc.NewIDTokens,
	oidc.NewDiscovery,
)

func provideKeyManager(
	cfg *config.Config,
	repo repository.SigningKeyRepository,
	logger *slog.Logger,
) (*keys.Manager, error) {
	mgr, err := keys.NewManager(context.Background(), cfg, repo, logger)
	if err != nil {
		return nil, fmt.Errorf("signing keys: %w", err)
	}
	return mgr, nil
}
