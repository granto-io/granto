package csrf

import (
	"errors"
	"strings"
	"testing"
)

func TestService_RoundTrip(t *testing.T) {
	t.Parallel()

	s := New("test-secret")
	token := s.Token("challenge-1")
	if token == "" {
		t.Fatal("empty token")
	}
	if err := s.Verify("challenge-1", token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestService_RejectsMismatch(t *testing.T) {
	t.Parallel()

	s := New("test-secret")
	token := s.Token("challenge-1")

	for _, tc := range []struct {
		name      string
		challenge string
		token     string
	}{
		{name: "other challenge", challenge: "challenge-2", token: token},
		{name: "tampered token", challenge: "challenge-1", token: token[:len(token)-1] + "A"},
		{name: "empty challenge", challenge: "", token: token},
		{name: "empty token", challenge: "challenge-1", token: ""},
	} {
		if err := s.Verify(tc.challenge, tc.token); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("%s: err = %v, want ErrInvalidToken", tc.name, err)
		}
	}
}

func TestService_RandomKeyPerProcess(t *testing.T) {
	t.Parallel()

	a, b := New(""), New("")
	if a.Token("challenge") == b.Token("challenge") {
		t.Fatal("expected distinct keys for empty secrets")
	}
	if strings.TrimSpace(a.Token("challenge")) == "" {
		t.Fatal("empty token")
	}
}

func TestService_StableForSameSecret(t *testing.T) {
	t.Parallel()

	a, b := New("shared"), New("shared")
	if a.Token("challenge") != b.Token("challenge") {
		t.Fatal("tokens differ for the same secret")
	}
}
