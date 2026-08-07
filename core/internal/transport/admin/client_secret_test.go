package admin

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewClientSecret(t *testing.T) {
	plain, hash, err := newClientSecret()
	if err != nil {
		t.Fatalf("newClientSecret() unexpected error: %v", err)
	}
	if plain == "" {
		t.Fatalf("newClientSecret() plaintext is empty, want non-empty secret")
	}
	if hash == "" {
		t.Fatalf("newClientSecret() hash is empty, want bcrypt hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		t.Fatalf("bcrypt.CompareHashAndPassword(hash, plaintext) failed: %v (hash should verify generated secret)", err)
	}

	plain2, hash2, err := newClientSecret()
	if err != nil {
		t.Fatalf("second newClientSecret() unexpected error: %v", err)
	}
	if plain == plain2 {
		t.Fatalf("two newClientSecret() calls returned the same plaintext %q; secrets must be unique", plain)
	}
	if hash == hash2 {
		t.Fatalf("two newClientSecret() calls returned the same hash; hashes must differ")
	}
}

func TestHashClientSecret(t *testing.T) {
	const secret = "super-secret"
	hash, err := hashClientSecret(secret)
	if err != nil {
		t.Fatalf("hashClientSecret(%q) unexpected error: %v", secret, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)); err != nil {
		t.Fatalf("hash does not verify plaintext %q: %v", secret, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
		t.Fatalf("hash unexpectedly verified wrong plaintext %q", "wrong")
	}
}
