package domain

import (
	"testing"
	"time"
)

func TestLoginChallengeIsExpired(t *testing.T) {
	t.Parallel()

	if !(*LoginChallenge)(nil).IsExpired() {
		t.Fatal("nil LoginChallenge IsExpired() = false, want true")
	}

	alive := &LoginChallenge{ExpiresAt: time.Now().Add(time.Minute)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired() = true, want false")
	}

	dead := &LoginChallenge{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired() = false, want true")
	}
}

func TestLoginChallengeValidAcceptToken(t *testing.T) {
	t.Parallel()

	c := &LoginChallenge{AcceptToken: "secret-token-value-32chars-ok!!"}
	if !c.ValidAcceptToken("secret-token-value-32chars-ok!!") {
		t.Fatal("matching token ValidAcceptToken = false, want true")
	}
	if c.ValidAcceptToken("other") {
		t.Fatal("wrong token ValidAcceptToken = true, want false")
	}
	if c.ValidAcceptToken("") {
		t.Fatal("empty token ValidAcceptToken = true, want false")
	}
	if (*LoginChallenge)(nil).ValidAcceptToken("x") {
		t.Fatal("nil challenge ValidAcceptToken = true, want false")
	}
	if (&LoginChallenge{}).ValidAcceptToken("") {
		t.Fatal("empty AcceptToken ValidAcceptToken(\"\") = true, want false")
	}
}

func TestNewAcceptToken(t *testing.T) {
	t.Parallel()

	a, err := NewAcceptToken()
	if err != nil {
		t.Fatalf("NewAcceptToken error: %v", err)
	}
	b, err := NewAcceptToken()
	if err != nil {
		t.Fatalf("NewAcceptToken error: %v", err)
	}
	if len(a) != 64 {
		t.Fatalf("NewAcceptToken len = %d, want 64 hex chars", len(a))
	}
	if a == b {
		t.Fatal("NewAcceptToken returned identical values twice")
	}
}
