package di

import (
	"github.com/google/wire"

	identityv1 "github.com/granto-io/granto/identity/gen/identity/v1"
	"github.com/granto-io/granto/identity/internal/transport/identity"
)

// IdentitySet provides the IdentityService gRPC service and server.
var IdentitySet = wire.NewSet(
	identity.NewService,
	wire.Bind(new(identityv1.IdentityServiceServer), new(*identity.Service)),
	identity.NewServer,
)
