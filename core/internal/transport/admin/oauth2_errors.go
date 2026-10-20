package admin

import (
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func oauth2ErrToStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, oauth2.ErrInvalidRequest):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, oauth2.ErrChallengeNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, oauth2.ErrChallengeExpired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, oauth2.ErrAcceptTokenInvalid):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, domain.ErrLoginChallengeNotFound),
		errors.Is(err, domain.ErrConsentChallengeNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrLoginChallengeExpired),
		errors.Is(err, domain.ErrConsentChallengeExpired):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, domain.ErrLoginChallengeAcceptTokenInvalid),
		errors.Is(err, domain.ErrConsentChallengeAcceptTokenInvalid):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

func uuidString(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}
