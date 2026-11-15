package adminclient

import (
	"testing"
)

func TestIsLoopbackHost(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"127.0.0.1", "::1", "[::1]", "localhost", "LOCALHOST"} {
		if !isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"core", "core.internal", "10.0.0.1", ""} {
		if isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = true, want false", host)
		}
	}
}

func TestTransportCredentials_LoopbackIsPlaintext(t *testing.T) {
	t.Parallel()

	creds, err := transportCredentials("127.0.0.1", "")
	if err != nil {
		t.Fatalf("transportCredentials: %v", err)
	}
	if got := creds.Info().SecurityProtocol; got != "insecure" {
		t.Fatalf("SecurityProtocol = %q, want insecure", got)
	}
}

func TestTransportCredentials_NonLoopbackRequiresTLS(t *testing.T) {
	t.Parallel()

	creds, err := transportCredentials("core.internal", "")
	if err != nil {
		t.Fatalf("transportCredentials: %v", err)
	}
	if got := creds.Info().SecurityProtocol; got != "tls" {
		t.Fatalf("SecurityProtocol = %q, want tls", got)
	}
}

func TestTransportCredentials_MissingCA(t *testing.T) {
	t.Parallel()

	if _, err := transportCredentials("core.internal", "/does/not/exist.pem"); err == nil {
		t.Fatal("expected an error for a missing CA file")
	}
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "empty addr", cfg: Config{Token: "t"}},
		{name: "empty token", cfg: Config{Addr: "127.0.0.1:4446"}},
		{name: "addr without port", cfg: Config{Addr: "localhost", Token: "t"}},
	} {
		if _, err := New(tc.cfg); err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
	}
}

func TestNew_Loopback(t *testing.T) {
	t.Parallel()

	c, err := New(Config{Addr: "127.0.0.1:4446", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
