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

	t.Run("other errors become Internal without leaking details", func(t *testing.T) {
		err := domainErrToStatus(errors.New("pq: duplicate key value violates unique constraint clients_tenant_id_client_id_key"))
		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("domainErrToStatus = %v, want gRPC status", err)
		}
		if st.Code() != codes.Internal {
			t.Fatalf("status code = %v, want %v; message=%q", st.Code(), codes.Internal, st.Message())
		}
		if st.Message() != "internal error" {
			t.Fatalf("message = %q, want generic %q", st.Message(), "internal error")
		}
	})
}

func TestOAuth2ErrToStatus_InternalDoesNotLeak(t *testing.T) {
	t.Parallel()
	err := oauth2ErrToStatus(errors.New("redis: connection refused to 10.0.0.5:6379"))
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("oauth2ErrToStatus = %v, want gRPC status", err)
	}
	if st.Code() != codes.Internal || st.Message() != "internal error" {
		t.Fatalf("status = %v %q, want Internal/internal error", st.Code(), st.Message())
	}
}
