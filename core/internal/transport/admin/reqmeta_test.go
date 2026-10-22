package admin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/granto-io/granto/core/internal/reqmeta"
)

func TestGatewayRequestMetadata(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/clients", nil)
	r.RemoteAddr = "203.0.113.10:54321"
	r.Header.Set("User-Agent", "curl/8.0")

	md := gatewayRequestMetadata(context.Background(), r)
	if got := firstMD(md, mdClientIP); got != "203.0.113.10" {
		t.Fatalf("client-ip=%q, want 203.0.113.10", got)
	}
	if got := firstMD(md, mdUserAgent); got != "curl/8.0" {
		t.Fatalf("user-agent=%q, want curl/8.0", got)
	}
}

func TestReqmetaUnaryInterceptorFromMetadata(t *testing.T) {
	t.Parallel()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		mdClientIP, "198.51.100.7",
		mdUserAgent, "admin-ui/1.0",
	))
	// Peer would be loopback via gateway — metadata must win.
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4446}})

	interceptor := reqmetaUnaryInterceptor()
	var gotIP net.IP
	var gotUA string
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		gotIP = reqmeta.IP(ctx)
		gotUA = reqmeta.UserAgent(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if !gotIP.Equal(net.ParseIP("198.51.100.7")) {
		t.Fatalf("IP=%v, want 198.51.100.7", gotIP)
	}
	if gotUA != "admin-ui/1.0" {
		t.Fatalf("UA=%q, want admin-ui/1.0", gotUA)
	}
}

func TestReqmetaUnaryInterceptorPeerFallback(t *testing.T) {
	t.Parallel()
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9999},
	})
	interceptor := reqmetaUnaryInterceptor()
	var gotIP net.IP
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		gotIP = reqmeta.IP(ctx)
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if !gotIP.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("IP=%v, want 192.0.2.1", gotIP)
	}
}

func firstMD(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}
