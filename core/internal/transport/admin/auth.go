package admin

import (
	"context"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func bearerAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if token == "" {
			return handler(ctx, req)
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
		return handler(ctx, req)
	}
}

func ipAllowlistInterceptor(allowed []string) grpc.UnaryServerInterceptor {
	set := make(map[string]struct{}, len(allowed))
	for _, ip := range allowed {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			set[ip] = struct{}{}
		}
	}
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if len(set) == 0 {
			return handler(ctx, req)
		}
		p, ok := peer.FromContext(ctx)
		if !ok || p.Addr == nil {
			return nil, status.Error(codes.PermissionDenied, "unknown peer")
		}
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			host = p.Addr.String()
		}
		if _, ok := set[host]; !ok {
			return nil, status.Error(codes.PermissionDenied, "ip not allowed")
		}
		return handler(ctx, req)
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
