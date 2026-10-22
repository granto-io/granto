package di

import (
	"github.com/google/wire"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/transport/admin"
)

// AdminSet provides Admin API gRPC services and the admin Server (gRPC + gateway).
var AdminSet = wire.NewSet(
	oauth2.NewFlow,
	admin.NewClientServer,
	wire.Bind(new(adminv1.ClientServiceServer), new(*admin.ClientServer)),
	admin.NewOAuth2Server,
	wire.Bind(new(adminv1.OAuth2ServiceServer), new(*admin.OAuth2Server)),
	admin.NewLoginSessionServer,
	wire.Bind(new(adminv1.LoginSessionServiceServer), new(*admin.LoginSessionServer)),
	admin.NewConsentGrantServer,
	wire.Bind(new(adminv1.ConsentGrantServiceServer), new(*admin.ConsentGrantServer)),
	admin.NewServer,
)
