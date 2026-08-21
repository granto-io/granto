package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConsentChallengeIsExpired(t *testing.T) {
	t.Parallel()

	if !(*ConsentChallenge)(nil).IsExpired() {
		t.Fatal("nil ConsentChallenge IsExpired() = false, want true")
	}

	alive := &ConsentChallenge{ExpiresAt: time.Now().Add(time.Minute)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired() = true, want false")
	}

	dead := &ConsentChallenge{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired() = false, want true")
	}
}

func TestConsentChallengeValidAcceptToken(t *testing.T) {
	t.Parallel()

	c := &ConsentChallenge{
		ID:          uuid.New(),
		AcceptToken: "secret-token-value-32chars-ok!!",
	}
	if !c.ValidAcceptToken("secret-token-value-32chars-ok!!") {
		t.Fatal("matching token ValidAcceptToken = false, want true")
	}
	if c.ValidAcceptToken("other") {
		t.Fatal("wrong token ValidAcceptToken = true, want false")
	}
	if c.ValidAcceptToken("") {
		t.Fatal("empty token ValidAcceptToken = true, want false")
	}
}
