package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/postgres"
)

const loginSessionColumns = `
	id,
	tenant_id,
	subject,
	authenticated_at,
	expires_at,
	remember,
	device_id,
	acr,
	amr,
	identity_provider_session_id,
	metadata,
	created_at,
	updated_at`

// LoginSessionRepository is the PostgreSQL implementation of repository.LoginSessionRepository.
type LoginSessionRepository struct {
	db *postgres.DB
}

// NewLoginSessionRepository constructs a login-session repository using the shared DB handle.
func NewLoginSessionRepository(db *postgres.DB) *LoginSessionRepository {
	return &LoginSessionRepository{db: db}
}

func (r *LoginSessionRepository) Create(ctx context.Context, s *domain.LoginSession) error {
	const q = `
		INSERT INTO login_sessions (
			id,
			tenant_id,
			subject,
			authenticated_at,
			expires_at,
			remember,
			device_id,
			acr,
			amr,
			identity_provider_session_id,
			metadata
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
			$10,
			$11
		)`

	meta, err := marshalJSONMap(s.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	amr := s.AMR
	if amr == nil {
		amr = []string{}
	}

	id := s.ID
	if id == uuid.Nil {
		id = uuid.New()
		s.ID = id
	}

	_, err = r.db.Conn(ctx).Exec(
		ctx,
		q,
		id,
		s.TenantID,
		s.Subject,
		s.AuthenticatedAt,
		s.ExpiresAt,
		s.Remember,
		s.DeviceID,
		s.ACR,
		amr,
		nullableStr(s.IdentityProviderSessionID),
		meta,
	)
	if err != nil {
		return fmt.Errorf("create login session: %w", err)
	}
	return nil
}

func (r *LoginSessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.LoginSession, error) {
	const q = `SELECT` + loginSessionColumns + `
		FROM login_sessions
		WHERE id = $1`
	s, err := scanLoginSession(r.db.Conn(ctx).QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrLoginSessionNotFound
	}
	return s, err
}

func (r *LoginSessionRepository) ListBySubject(ctx context.Context, tenantID uuid.UUID, subject string) ([]*domain.LoginSession, error) {
	const q = `SELECT` + loginSessionColumns + `
		FROM login_sessions
		WHERE tenant_id = $1
		  AND subject = $2
		ORDER BY authenticated_at DESC`

	return r.list(ctx, q, tenantID, subject)
}

func (r *LoginSessionRepository) ListByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID string) ([]*domain.LoginSession, error) {
	const q = `SELECT` + loginSessionColumns + `
		FROM login_sessions
		WHERE tenant_id = $1
		  AND device_id = $2
		ORDER BY authenticated_at DESC`

	return r.list(ctx, q, tenantID, deviceID)
}

func (r *LoginSessionRepository) list(ctx context.Context, q string, args ...any) ([]*domain.LoginSession, error) {
	rows, err := r.db.Conn(ctx).Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list login sessions: %w", err)
	}
	defer rows.Close()

	var out []*domain.LoginSession
	for rows.Next() {
		s, err := scanLoginSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *LoginSessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `
		DELETE FROM login_sessions
		WHERE id = $1`
	tag, err := r.db.Conn(ctx).Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete login session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrLoginSessionNotFound
	}
	return nil
}

func (r *LoginSessionRepository) DeleteBySubject(ctx context.Context, tenantID uuid.UUID, subject string) error {
	const q = `
		DELETE FROM login_sessions
		WHERE tenant_id = $1
		  AND subject = $2`
	_, err := r.db.Conn(ctx).Exec(ctx, q, tenantID, subject)
	if err != nil {
		return fmt.Errorf("delete login sessions by subject: %w", err)
	}
	return nil
}

func scanLoginSession(row scanner) (*domain.LoginSession, error) {
	var (
		id, tenantID    uuid.UUID
		subject         string
		authenticatedAt time.Time
		expiresAt       time.Time
		remember        bool
		deviceID        string
		acr             string
		amr             []string
		idpSessionID    pgtype.Text
		metaRaw         []byte
		createdAt       time.Time
		updatedAt       time.Time
	)

	err := row.Scan(
		&id,
		&tenantID,
		&subject,
		&authenticatedAt,
		&expiresAt,
		&remember,
		&deviceID,
		&acr,
		&amr,
		&idpSessionID,
		&metaRaw,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}

	meta, err := unmarshalJSONMap(metaRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &domain.LoginSession{
		ID:                        id,
		TenantID:                  tenantID,
		Subject:                   subject,
		AuthenticatedAt:           authenticatedAt,
		ExpiresAt:                 expiresAt,
		Remember:                  remember,
		DeviceID:                  deviceID,
		ACR:                       acr,
		AMR:                       amr,
		IdentityProviderSessionID: idpSessionID.String,
		Metadata:                  meta,
		CreatedAt:                 createdAt,
		UpdatedAt:                 updatedAt,
	}, nil
}
