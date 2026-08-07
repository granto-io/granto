package di

import (
	"github.com/google/wire"

	adminv1 "github.com/granto-io/granto/core/gen/admin/v1"
	"github.com/granto-io/granto/core/internal/transport/admin"
)

// AdminSet provides Admin API gRPC services and the admin Server (gRPC + gateway).
var AdminSet = wire.NewSet(
	admin.NewClientServer,
	wire.Bind(new(adminv1.ClientServiceServer), new(*admin.ClientServer)),
	admin.NewServer,
)
