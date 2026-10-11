package domain

import (
	"testing"
	"time"
)

func TestAccessTokenIsExpired(t *testing.T) {
	t.Parallel()
	if !(*AccessToken)(nil).IsExpired() {
		t.Fatal("nil AccessToken IsExpired = false, want true")
	}
	alive := &AccessToken{ExpiresAt: time.Now().Add(time.Minute)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired = true")
	}
	dead := &AccessToken{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired = false")
	}
}

func TestRefreshTokenIsExpired(t *testing.T) {
	t.Parallel()
	if !(*RefreshToken)(nil).IsExpired() {
		t.Fatal("nil RefreshToken IsExpired = false, want true")
	}
	alive := &RefreshToken{ExpiresAt: time.Now().Add(time.Hour)}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired = true")
	}
	dead := &RefreshToken{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired = false")
	}
}

func TestHashToken(t *testing.T) {
	t.Parallel()
	a := HashToken("tok")
	b := HashToken("tok")
	c := HashToken("other")
	if a != b || a == c || len(a) != 64 {
		t.Fatalf("HashToken unexpected: a=%q b=%q c=%q", a, b, c)
	}
	if HashAuthorizationCode("tok") != a {
		t.Fatal("HashAuthorizationCode and HashToken should match for same input")
	}
}
