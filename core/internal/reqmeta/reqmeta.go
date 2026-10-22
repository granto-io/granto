package reqmeta

import (
	"context"
	"net"
	"net/http"
	"strings"
)

type ctxKey int

const (
	keyIP ctxKey = iota + 1
	keyUA
)

// WithRequestMeta stores client IP (from RemoteAddr) and User-Agent on ctx.
// X-Forwarded-For is not trusted in MVP (no trusted-proxy config yet).
//
// Note: context values do not cross a network gRPC hop (e.g. Admin REST
// grpc-gateway → gRPC server). For that path, transport must re-attach via
// WithIP / WithUserAgent after reading gRPC metadata / peer.
func WithRequestMeta(ctx context.Context, r *http.Request) context.Context {
	if r == nil {
		return ctx
	}
	if ua := strings.TrimSpace(r.UserAgent()); ua != "" {
		ctx = WithUserAgent(ctx, ua)
	}
	if ip := ClientIPFromRemoteAddr(r.RemoteAddr); ip != nil {
		ctx = WithIP(ctx, ip)
	}
	return ctx
}

// WithIP stores a client IP on ctx (nil is a no-op).
func WithIP(ctx context.Context, ip net.IP) context.Context {
	if ip == nil {
		return ctx
	}
	return context.WithValue(ctx, keyIP, ip)
}

// WithUserAgent stores a User-Agent on ctx (empty is a no-op).
func WithUserAgent(ctx context.Context, ua string) context.Context {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return ctx
	}
	return context.WithValue(ctx, keyUA, ua)
}

// Middleware injects IP / User-Agent into the request context (in-process HTTP).
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithRequestMeta(r.Context(), r)))
	})
}

// IP returns the client IP from ctx, if set.
func IP(ctx context.Context) net.IP {
	ip, _ := ctx.Value(keyIP).(net.IP)
	return ip
}

// UserAgent returns the User-Agent from ctx, if set.
func UserAgent(ctx context.Context) string {
	ua, _ := ctx.Value(keyUA).(string)
	return ua
}

// ClientIPFromRemoteAddr parses host from "host:port" (or bare host) RemoteAddr.
func ClientIPFromRemoteAddr(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(host)
}
