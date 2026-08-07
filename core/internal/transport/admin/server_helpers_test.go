package admin

import (
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func TestDialLocal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in, want string
	}{
		{name: "port-only becomes loopback", in: ":4446", want: "127.0.0.1:4446"},
		{name: "explicit loopback unchanged", in: "127.0.0.1:4446", want: "127.0.0.1:4446"},
		{name: "hostname unchanged", in: "localhost:4446", want: "localhost:4446"},
		{name: "empty unchanged", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := dialLocal(tc.in)
			if got != tc.want {
				t.Fatalf("dialLocal(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestIncomingHeaderMatcher(t *testing.T) {
	t.Parallel()

	t.Run("authorization is always forwarded", func(t *testing.T) {
		for _, key := range []string{"Authorization", "authorization", "AUTHORIZATION"} {
			out, ok := incomingHeaderMatcher(key)
			if !ok {
				t.Fatalf("incomingHeaderMatcher(%q) ok = false, want true", key)
			}
			if out != "authorization" {
				t.Fatalf("incomingHeaderMatcher(%q) = %q, want %q", key, out, "authorization")
			}
		}
	})

	t.Run("other headers use gateway default matcher", func(t *testing.T) {
		const key = "X-Custom"
		out, ok := incomingHeaderMatcher(key)
		def, defOK := runtime.DefaultHeaderMatcher(key)
		if out != def || ok != defOK {
			t.Fatalf("incomingHeaderMatcher(%q) = (%q, %v), want default (%q, %v)", key, out, ok, def, defOK)
		}
	})
}
