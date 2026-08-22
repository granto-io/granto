package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFlowVerifierKindQueryParam(t *testing.T) {
	t.Parallel()
	if got := FlowVerifierKindLogin.QueryParam(); got != "login_verifier" {
		t.Fatalf("login QueryParam = %q, want login_verifier", got)
	}
	if got := FlowVerifierKindConsent.QueryParam(); got != "consent_verifier" {
		t.Fatalf("consent QueryParam = %q, want consent_verifier", got)
	}
}

func TestFlowVerifierIsExpired(t *testing.T) {
	t.Parallel()
	if !(*FlowVerifier)(nil).IsExpired() {
		t.Fatal("nil IsExpired = false, want true")
	}
	alive := &FlowVerifier{ExpiresAt: time.Now().Add(time.Minute)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired = true, want false")
	}
	dead := &FlowVerifier{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired = false, want true")
	}
}

func TestFlowVerifierValidKind(t *testing.T) {
	t.Parallel()
	ok := &FlowVerifier{ID: uuid.New(), Kind: FlowVerifierKindLogin}
	if !ok.ValidKind() {
		t.Fatal("login ValidKind = false")
	}
	bad := &FlowVerifier{Kind: "nope"}
	if bad.ValidKind() {
		t.Fatal("unknown Kind ValidKind = true")
	}
}
