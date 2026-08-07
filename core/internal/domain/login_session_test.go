package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLoginSessionIsExpired(t *testing.T) {
	t.Parallel()

	if !(*LoginSession)(nil).IsExpired() {
		t.Fatal("nil LoginSession IsExpired() = false, want true")
	}

	alive := &LoginSession{
		ID:        uuid.New(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if alive.IsExpired() {
		t.Fatal("future ExpiresAt IsExpired() = true, want false")
	}

	dead := &LoginSession{ExpiresAt: time.Now().Add(-time.Second)}
	if !dead.IsExpired() {
		t.Fatal("past ExpiresAt IsExpired() = false, want true")
	}
}
