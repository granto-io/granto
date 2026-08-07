package admin

import (
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

func TestDialLocal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{":4446", "127.0.0.1:4446"},
		{"127.0.0.1:4446", "127.0.0.1:4446"},
		{"localhost:4446", "localhost:4446"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := dialLocal(tc.in); got != tc.want {
			t.Fatalf("dialLocal(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestIncomingHeaderMatcher(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"Authorization", "authorization", "AUTHORIZATION"} {
		out, ok := incomingHeaderMatcher(key)
		if !ok || out != "authorization" {
			t.Fatalf("%q → %q ok=%v", key, out, ok)
		}
	}
	out, ok := incomingHeaderMatcher("X-Custom")
	def, defOK := runtime.DefaultHeaderMatcher("X-Custom")
	if out != def || ok != defOK {
		t.Fatalf("custom: got %q/%v want %q/%v", out, ok, def, defOK)
	}
}
