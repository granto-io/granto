package admin

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/granto-io/granto/core/internal/domain"
)

func TestDomainErrToStatus(t *testing.T) {
	t.Parallel()

	if err := domainErrToStatus(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}

	st, ok := status.FromError(domainErrToStatus(domain.ErrClientNotFound))
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("not found: %v", domainErrToStatus(domain.ErrClientNotFound))
	}

	wrapped := errors.Join(errors.New("wrap"), domain.ErrClientNotFound)
	st, ok = status.FromError(domainErrToStatus(wrapped))
	if !ok || st.Code() != codes.NotFound {
		t.Fatalf("wrapped not found: %v", domainErrToStatus(wrapped))
	}

	st, ok = status.FromError(domainErrToStatus(errors.New("boom")))
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("other: %v", domainErrToStatus(errors.New("boom")))
	}
}
