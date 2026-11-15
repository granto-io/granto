package identityclient

import (
	"testing"
)

func TestNew_RequiresAddr(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestNew_AcceptsContainerHostname(t *testing.T) {
	t.Parallel()
	// Not loopback, e.g. a Docker Compose service DNS name: the trust
	// boundary is "operator does not expose the port", not "dial address
	// must be literally 127.0.0.1" (see New's doc comment).
	c, err := New(Config{Addr: "identity.internal:4456"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestNew_RejectsMissingPort(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{Addr: "identity.internal"}); err == nil {
		t.Fatal("expected error for addr without a port")
	}
}

func TestNew_AcceptsLoopback(t *testing.T) {
	t.Parallel()
	c, err := New(Config{Addr: "127.0.0.1:4456"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}

func TestNew_AcceptsLocalhost(t *testing.T) {
	t.Parallel()
	c, err := New(Config{Addr: "localhost:4456"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
}
