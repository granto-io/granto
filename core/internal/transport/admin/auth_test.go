package admin

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestSubtleConstantTimeEq(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{name: "both empty", a: "", b: "", want: true},
		{name: "equal", a: "abc", b: "abc", want: true},
		{name: "same length different", a: "abc", b: "abd", want: false},
		{name: "a longer", a: "abc", b: "ab", want: false},
		{name: "b longer", a: "ab", b: "abc", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := subtleConstantTimeEq(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("subtleConstantTimeEq(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestBearerAuthInterceptor(t *testing.T) {
	t.Parallel()
	okHandler := func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	}

	t.Run("empty configured token allows all requests", func(t *testing.T) {
		interceptor := bearerAuthInterceptor("")
		got, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil {
			t.Fatalf("interceptor error = %v, want nil", err)
		}
		if got != "ok" {
			t.Fatalf("handler result = %#v, want %q", got, "ok")
		}
	})

	interceptor := bearerAuthInterceptor("secret")

	t.Run("missing metadata is unauthenticated", func(t *testing.T) {
		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("missing authorization header is unauthenticated", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("non-bearer scheme is unauthenticated", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic secret"))
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("wrong bearer token is unauthenticated", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer other"))
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		assertStatusCode(t, err, codes.Unauthenticated)
	})

	t.Run("matching bearer token passes through", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer secret"))
		got, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, okHandler)
		if err != nil {
			t.Fatalf("interceptor error = %v, want nil", err)
		}
		if got != "ok" {
			t.Fatalf("handler result = %#v, want %q", got, "ok")
		}
	})
}

func assertStatusCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want gRPC status code %v", code)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error = %v (%T), want gRPC status with code %v", err, err, code)
	}
	if st.Code() != code {
		t.Fatalf("gRPC status code = %v (%q), want %v", st.Code(), st.Message(), code)
	}
}
