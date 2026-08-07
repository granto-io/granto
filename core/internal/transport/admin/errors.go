package admin

import (
	"errors"

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
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}
