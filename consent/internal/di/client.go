package di

import (
	"fmt"

	"github.com/google/wire"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/config"
	"github.com/granto-io/granto/consent/internal/identityclient"
)

// ClientSet provides the core Admin and identity gRPC clients.
var ClientSet = wire.NewSet(
	provideAdminClient,
	provideIdentityClient,
)

func provideAdminClient(cfg *config.Config) (adminclient.Client, error) {
	c, err := adminclient.New(adminclient.Config{
		Addr:      cfg.Core.AdminAddr,
		Token:     cfg.Core.AdminToken,
		TLSCAFile: cfg.Core.AdminTLSCAFile,
	})
	if err != nil {
		return nil, fmt.Errorf("admin client: %w", err)
	}
	return c, nil
}

func provideIdentityClient(cfg *config.Config) (*identityclient.Client, error) {
	c, err := identityclient.New(identityclient.Config{Addr: cfg.Identity.Addr})
	if err != nil {
		return nil, fmt.Errorf("identity client: %w", err)
	}
	return c, nil
}
