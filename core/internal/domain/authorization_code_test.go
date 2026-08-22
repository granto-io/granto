package domain

import (
	"testing"
	"time"
)

func TestAuthorizationCodeIsExpired(t *testing.T) {
	t.Parallel()
	if !(*AuthorizationCode)(nil).IsExpired() {
		t.Fatal("nil IsExpired = false, want true")
	}
	alive := &AuthorizationCode{ExpiresAt: time.Now().Add(time.Minute)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired = true, want false")
	}
	dead := &AuthorizationCode{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired = false, want true")
	}
}

func TestHashAuthorizationCode(t *testing.T) {
	t.Parallel()
	a := HashAuthorizationCode("abc")
	b := HashAuthorizationCode("abc")
	c := HashAuthorizationCode("xyz")
	if a != b {
		t.Fatal("same input produced different hashes")
	}
	if a == c {
		t.Fatal("different inputs produced same hash")
	}
	if len(a) != 64 {
		t.Fatalf("hash len = %d, want 64", len(a))
	}
}
