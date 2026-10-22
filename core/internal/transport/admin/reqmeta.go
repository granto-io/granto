package admin

import (
	"context"
	"net"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/granto-io/granto/core/internal/reqmeta"
)

// gRPC metadata keys for client IP / UA across the Admin REST gateway hop.
// context.WithValue from HTTP middleware does not survive grpc.NewClient.
const (
	mdClientIP  = "x-granto-client-ip"
	mdUserAgent = "x-granto-user-agent"
)

// gatewayRequestMetadata copies the caller's RemoteAddr / User-Agent into
// outgoing gRPC metadata so the Admin gRPC server can restore reqmeta.
func gatewayRequestMetadata(_ context.Context, r *http.Request) metadata.MD {
	md := metadata.MD{}
	if r == nil {
		return md
	}
	if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
		md.Set(mdUserAgent, ua)
	}
	if ip := reqmeta.ClientIPFromRemoteAddr(r.RemoteAddr); ip != nil {
		md.Set(mdClientIP, ip.String())
	}
	return md
}

// reqmetaUnaryInterceptor attaches IP / User-Agent to the handler ctx.
// Prefer gateway-forwarded metadata (real HTTP client); fall back to gRPC peer
// (direct Admin gRPC callers — often loopback when via gateway).
func reqmetaUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		return handler(attachRequestMeta(ctx), req)
	}
}

func attachRequestMeta(ctx context.Context) context.Context {
	if ip := clientIPFromIncoming(ctx); ip != nil {
		ctx = reqmeta.WithIP(ctx, ip)
	}
	if ua := userAgentFromIncoming(ctx); ua != "" {
		ctx = reqmeta.WithUserAgent(ctx, ua)
	}
	return ctx
}

func clientIPFromIncoming(ctx context.Context) net.IP {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get(mdClientIP); len(vals) > 0 {
			if ip := net.ParseIP(strings.TrimSpace(vals[0])); ip != nil {
				return ip
			}
		}
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return nil
	}
	return reqmeta.ClientIPFromRemoteAddr(p.Addr.String())
}

func userAgentFromIncoming(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{mdUserAgent, "grpcgateway-user-agent", "user-agent"} {
		if vals := md.Get(key); len(vals) > 0 {
			if ua := strings.TrimSpace(vals[0]); ua != "" {
				return ua
			}
		}
	}
	return ""
}

// reqmetaMiddleware keeps HTTP ctx values for any in-process readers; the
// Admin gRPC hop relies on gatewayRequestMetadata + reqmetaUnaryInterceptor.
func reqmetaMiddleware(next http.Handler) http.Handler {
	return reqmeta.Middleware(next)
}
