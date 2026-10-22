package admin

import (
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/granto-io/granto/core/internal/domain"
)

func domainErrToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, domain.ErrClientNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrLoginSessionNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return internalStatus(err)
	}
}

// internalStatus logs the real error server-side and returns a generic gRPC
// Internal to the client (same idea as public OAuth handlers).
func internalStatus(err error) error {
	slog.Error("admin internal error", "err", err)
	return status.Error(codes.Internal, "internal error")
}
