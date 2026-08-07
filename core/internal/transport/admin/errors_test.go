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

	t.Run("nil error stays nil", func(t *testing.T) {
		if err := domainErrToStatus(nil); err != nil {
			t.Fatalf("domainErrToStatus(nil) = %v, want nil", err)
		}
	})

	t.Run("client not found becomes NotFound", func(t *testing.T) {
		err := domainErrToStatus(domain.ErrClientNotFound)
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("domainErrToStatus(ErrClientNotFound) = %v, want gRPC status", err)
		}
		if st.Code() != codes.NotFound {
			t.Fatalf("status code = %v, want %v; message=%q", st.Code(), codes.NotFound, st.Message())
		}
	})

	t.Run("wrapped client not found becomes NotFound", func(t *testing.T) {
		wrapped := errors.Join(errors.New("wrap"), domain.ErrClientNotFound)
		err := domainErrToStatus(wrapped)
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("domainErrToStatus(wrapped ErrClientNotFound) = %v, want gRPC status", err)
		}
		if st.Code() != codes.NotFound {
			t.Fatalf("status code = %v, want %v; message=%q", st.Code(), codes.NotFound, st.Message())
		}
	})

	t.Run("other errors become Internal", func(t *testing.T) {
		err := domainErrToStatus(errors.New("boom"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("domainErrToStatus(boom) = %v, want gRPC status", err)
		}
		if st.Code() != codes.Internal {
			t.Fatalf("status code = %v, want %v; message=%q", st.Code(), codes.Internal, st.Message())
		}
	})
}
