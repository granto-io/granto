package admin

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestNewClientSecret(t *testing.T) {
	plain, hash, err := newClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if plain == "" || hash == "" {
		t.Fatal("empty plain or hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)); err != nil {
		t.Fatalf("bcrypt verify: %v", err)
	}

	plain2, hash2, err := newClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if plain == plain2 || hash == hash2 {
		t.Fatal("secrets should differ across calls")
	}
}

func TestHashClientSecret(t *testing.T) {
	hash, err := hashClientSecret("super-secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("super-secret")); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
		t.Fatal("expected mismatch")
	}
}
