package admin

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/granto-io/granto/core/internal/domain"
)

func bearerAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Fail-closed: empty configured token must not open Admin (config.Load
		// already requires admin.token; this guards future construction paths).
		if token == "" {
			return nil, status.Error(codes.FailedPrecondition, "admin token not configured")
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		values := md.Get("authorization")
		if len(values) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization")
		}
		got := strings.TrimSpace(values[0])
		const prefix = "Bearer "
		if !strings.HasPrefix(got, prefix) || !subtleConstantTimeEq(got[len(prefix):], token) {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		// MVP: single Admin bearer → DefaultTenantID. Multi-tenant Admin tokens later.
		return handler(WithTenantID(ctx, domain.DefaultTenantID), req)
	}
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
