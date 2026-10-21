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

const consentGrantColumns = `
	id,
	tenant_id,
	subject,
	client_id,
	scopes,
	audience,
	expires_at,
	created_at,
	updated_at`

// ConsentGrantRepository is the Postgres implementation of repository.ConsentGrantRepository.
type ConsentGrantRepository struct {
	db *postgres.DB
}

// NewConsentGrantRepository constructs a consent-grant repository.
func NewConsentGrantRepository(db *postgres.DB) *ConsentGrantRepository {
	return &ConsentGrantRepository{db: db}
}

// Upsert inserts or replaces the grant for (tenant, subject, client).
func (r *ConsentGrantRepository) Upsert(ctx context.Context, g *domain.ConsentGrant) error {
	if g == nil {
		return fmt.Errorf("consent grant is nil")
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	now := time.Now().UTC()
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	g.UpdatedAt = now
	if g.Scopes == nil {
		g.Scopes = []string{}
	}
	if g.Audience == nil {
		g.Audience = []string{}
	}

	q := `
		INSERT INTO consent_grants (
			id,
			tenant_id,
			subject,
			client_id,
			scopes,
			audience,
			expires_at,
			created_at,
			updated_at
		) VALUES (
			$1,
			$2,
			$3,
			$4,
			$5,
			$6,
			$7,
			$8,
			$9
		)
		ON CONFLICT (tenant_id, subject, client_id) DO UPDATE SET
			scopes = EXCLUDED.scopes,
			audience = EXCLUDED.audience,
			expires_at = EXCLUDED.expires_at,
			updated_at = EXCLUDED.updated_at
		RETURNING` + consentGrantColumns

	row := r.db.Conn(ctx).QueryRow(ctx, q,
		g.ID,
		g.TenantID,
		g.Subject,
		g.ClientID,
		g.Scopes,
		g.Audience,
		g.ExpiresAt,
		g.CreatedAt,
		g.UpdatedAt,
	)
	got, err := scanConsentGrant(row)
	if err != nil {
		return fmt.Errorf("upsert consent grant: %w", err)
	}
	*g = *got
	return nil
}

// Get returns a non-expired grant, or ErrConsentGrantNotFound.
func (r *ConsentGrantRepository) Get(ctx context.Context, tenantID uuid.UUID, subject, clientID string) (*domain.ConsentGrant, error) {
	q := `
		SELECT` + consentGrantColumns + `
		FROM consent_grants
		WHERE tenant_id = $1
		  AND subject = $2
		  AND client_id = $3
		  AND (expires_at IS NULL OR expires_at > now())`

	row := r.db.Conn(ctx).QueryRow(ctx, q, tenantID, subject, clientID)
	g, err := scanConsentGrant(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrConsentGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get consent grant: %w", err)
	}
	return g, nil
}

// Delete removes a grant (idempotent).
func (r *ConsentGrantRepository) Delete(ctx context.Context, tenantID uuid.UUID, subject, clientID string) error {
	q := `
		DELETE FROM consent_grants
		WHERE tenant_id = $1
		  AND subject = $2
		  AND client_id = $3`
	_, err := r.db.Conn(ctx).Exec(ctx, q, tenantID, subject, clientID)
	if err != nil {
		return fmt.Errorf("delete consent grant: %w", err)
	}
	return nil
}

func scanConsentGrant(row scanner) (*domain.ConsentGrant, error) {
	var (
		g         domain.ConsentGrant
		expiresAt *time.Time
	)
	err := row.Scan(
		&g.ID,
		&g.TenantID,
		&g.Subject,
		&g.ClientID,
		&g.Scopes,
		&g.Audience,
		&expiresAt,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	g.ExpiresAt = expiresAt
	if g.Scopes == nil {
		g.Scopes = []string{}
	}
	if g.Audience == nil {
		g.Audience = []string{}
	}
	return &g, nil
}
