package admin

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestSubtleConstantTimeEq(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"ab", "abc", false},
	}
	for _, tc := range cases {
		if got := subtleConstantTimeEq(tc.a, tc.b); got != tc.want {
			t.Fatalf("eq(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBearerAuthInterceptor(t *testing.T) {
	t.Parallel()
	okHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	t.Run("empty token passthrough", func(t *testing.T) {
		interceptor := bearerAuthInterceptor("")
		got, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil || got != "ok" {
			t.Fatalf("got %v %v", got, err)
		}
	})

	interceptor := bearerAuthInterceptor("secret")

	t.Run("missing metadata", func(t *testing.T) {
		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("missing authorization", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("bad prefix", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic secret"))
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("wrong token", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer other"))
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("success", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer secret"))
		got, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil || got != "ok" {
			t.Fatalf("got %v %v", got, err)
		}
	})
}

func TestIPAllowlistInterceptor(t *testing.T) {
	t.Parallel()
	okHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	t.Run("empty allowlist passthrough", func(t *testing.T) {
		interceptor := ipAllowlistInterceptor(nil)
		got, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil || got != "ok" {
			t.Fatalf("got %v %v", got, err)
		}
	})

	interceptor := ipAllowlistInterceptor([]string{"127.0.0.1", " 10.0.0.1 "})

	t.Run("unknown peer", func(t *testing.T) {
		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.PermissionDenied)
	})

	t.Run("denied", func(t *testing.T) {
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("192.168.0.1"), Port: 1}})
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.PermissionDenied)
	})

	t.Run("allowed hostport", func(t *testing.T) {
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}})
		got, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil || got != "ok" {
			t.Fatalf("got %v %v", got, err)
		}
	})

	t.Run("allowed bare ip addr", func(t *testing.T) {
		ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: bareAddr("10.0.0.1")})
		got, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil || got != "ok" {
			t.Fatalf("got %v %v", got, err)
		}
	})
}

type bareAddr string

func (a bareAddr) Network() string { return "ip" }
func (a bareAddr) String() string  { return string(a) }

func assertStatusCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("want status error, got %v", err)
	}
	if st.Code() != code {
		t.Fatalf("code=%v want %v (%v)", st.Code(), code, err)
	}
}
