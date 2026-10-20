package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/postgres"
)

const signingKeyColumns = `
	id,
	tenant_id,
	kid,
	algorithm,
	use,
	public_key,
	private_key,
	is_active,
	rotated_at,
	expires_at,
	created_at`

// SigningKeyRepository is the Postgres implementation of repository.SigningKeyRepository.
type SigningKeyRepository struct {
	db *postgres.DB
}

// NewSigningKeyRepository constructs a signing-key repository.
func NewSigningKeyRepository(db *postgres.DB) *SigningKeyRepository {
	return &SigningKeyRepository{db: db}
}

// GetActiveKey returns the active signing key for tenant+algorithm.
func (r *SigningKeyRepository) GetActiveKey(ctx context.Context, tenantID uuid.UUID, algorithm string) (*domain.SigningKey, error) {
	q := `
		SELECT` + signingKeyColumns + `
		FROM signing_keys
		WHERE tenant_id = $1
		  AND algorithm = $2
		  AND is_active = true
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.db.Conn(ctx).QueryRow(ctx, q, tenantID, algorithm)
	k, err := scanSigningKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrSigningKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get active signing key: %w", err)
	}
	return k, nil
}

// ListActiveKeys returns active signing keys for JWKS (auto-gen path).
func (r *SigningKeyRepository) ListActiveKeys(ctx context.Context, tenantID uuid.UUID) ([]*domain.SigningKey, error) {
	q := `
		SELECT` + signingKeyColumns + `
		FROM signing_keys
		WHERE tenant_id = $1
		  AND is_active = true
		ORDER BY created_at DESC`

	rows, err := r.db.Conn(ctx).Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list active signing keys: %w", err)
	}
	defer rows.Close()

	var out []*domain.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Create inserts a signing key. Concurrent active inserts for the same
// tenant+algorithm are ignored (partial unique index).
func (r *SigningKeyRepository) Create(ctx context.Context, key *domain.SigningKey) error {
	if key.ID == uuid.Nil {
		key.ID = uuid.New()
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now().UTC()
	}

	q := `
		INSERT INTO signing_keys (
			id,
			tenant_id,
			kid,
			algorithm,
			use,
			public_key,
			private_key,
			is_active,
			expires_at,
			created_at
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9,
			$10
		)
		ON CONFLICT DO NOTHING`

	_, err := r.db.Conn(ctx).Exec(ctx, q,
		key.ID,
		key.TenantID,
		key.KID,
		key.Algorithm,
		key.Use,
		key.PublicKey,
		key.PrivateKey,
		key.IsActive,
		key.ExpiresAt,
		key.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create signing key: %w", err)
	}
	return nil
}

type signingKeyScanner interface {
	Scan(dest ...any) error
}

func scanSigningKey(row signingKeyScanner) (*domain.SigningKey, error) {
	var (
		k                    domain.SigningKey
		rotatedAt, expiresAt *time.Time
	)
	err := row.Scan(
		&k.ID,
		&k.TenantID,
		&k.KID,
		&k.Algorithm,
		&k.Use,
		&k.PublicKey,
		&k.PrivateKey,
		&k.IsActive,
		&rotatedAt,
		&expiresAt,
		&k.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	k.RotatedAt = rotatedAt
	k.ExpiresAt = expiresAt
	return &k, nil
}
