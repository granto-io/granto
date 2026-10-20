package domain

import (
	"time"

	"github.com/google/uuid"
)

// SigningKey is an AS signing key record (Postgres). PrivateKey is ciphertext
// (base64) when loaded from storage; static in-memory keys are not persisted.
type SigningKey struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	KID       string
	Algorithm string
	Use       string // "sig" | "enc"

	PublicKey  string // PEM
	PrivateKey string // base64(AES-GCM(private PEM)) when from DB

	IsActive  bool
	RotatedAt *time.Time
	ExpiresAt *time.Time
	CreatedAt time.Time
}
