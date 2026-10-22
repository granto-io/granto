package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/postgres"
	"github.com/granto-io/granto/core/internal/repository"
)

// AuditRepository is the Postgres durable audit outbox.
type AuditRepository struct {
	db     *postgres.DB
	logger *slog.Logger
}

// NewAuditRepository constructs an outbox-backed audit repository.
func NewAuditRepository(db *postgres.DB, logger *slog.Logger) *AuditRepository {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditRepository{db: db, logger: logger}
}

// Stop is a no-op for the outbox store (dispatcher lifecycle lives in audit.Bus).
func (r *AuditRepository) Stop() {}

// Log inserts the event payload into audit_outbox.
func (r *AuditRepository) Log(ctx context.Context, event *domain.AuditEvent) error {
	if event == nil {
		return nil
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.Outcome == "" {
		event.Outcome = domain.AuditOutcomeSuccess
	}
	payload, err := marshalAuditPayload(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	const q = `
		INSERT INTO audit_outbox (payload, created_at, next_attempt_at)
		VALUES ($1, $2, $2)`
	_, err = r.db.Conn(ctx).Exec(ctx, q, payload, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("enqueue audit outbox: %w", err)
	}
	return nil
}

// ClaimBatch selects due rows FOR UPDATE SKIP LOCKED, bumps attempts, and
// postpones next_attempt_at by lease so other workers do not steal them.
func (r *AuditRepository) ClaimBatch(ctx context.Context, limit int, lease time.Duration) ([]repository.AuditOutboxRow, error) {
	if limit <= 0 {
		limit = 50
	}
	if lease <= 0 {
		lease = 30 * time.Second
	}
	leaseUntil := time.Now().UTC().Add(lease)
	const q = `
		WITH due AS (
			SELECT id
			FROM audit_outbox
			WHERE next_attempt_at <= now()
			ORDER BY next_attempt_at ASC, id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE audit_outbox AS o
		SET
			attempts = o.attempts + 1,
			next_attempt_at = $2
		FROM due
		WHERE o.id = due.id
		RETURNING o.id, o.payload, o.created_at, o.attempts`

	rows, err := r.db.Conn(ctx).Query(ctx, q, limit, leaseUntil)
	if err != nil {
		return nil, fmt.Errorf("claim audit outbox: %w", err)
	}
	defer rows.Close()

	var out []repository.AuditOutboxRow
	for rows.Next() {
		var row repository.AuditOutboxRow
		if err := rows.Scan(&row.ID, &row.Payload, &row.CreatedAt, &row.Attempts); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// Ack deletes a delivered outbox row.
func (r *AuditRepository) Ack(ctx context.Context, id int64) error {
	_, err := r.db.Conn(ctx).Exec(ctx, `DELETE FROM audit_outbox WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("ack audit outbox: %w", err)
	}
	return nil
}

// Nack records failure and schedules the next attempt.
func (r *AuditRepository) Nack(ctx context.Context, id int64, backoff time.Duration, lastErr string) error {
	if backoff <= 0 {
		backoff = 5 * time.Second
	}
	next := time.Now().UTC().Add(backoff)
	const q = `
		UPDATE audit_outbox
		SET
			next_attempt_at = $2,
			last_error = $3
		WHERE id = $1`
	_, err := r.db.Conn(ctx).Exec(ctx, q, id, next, truncateErr(lastErr, 1000))
	if err != nil {
		return fmt.Errorf("nack audit outbox: %w", err)
	}
	return nil
}

func marshalAuditPayload(e *domain.AuditEvent) ([]byte, error) {
	type wire struct {
		TenantID    string         `json:"tenant_id"`
		EventType   string         `json:"event_type"`
		ActorType   string         `json:"actor_type"`
		ActorID     string         `json:"actor_id,omitempty"`
		SubjectType string         `json:"subject_type,omitempty"`
		SubjectID   string         `json:"subject_id,omitempty"`
		ClientID    string         `json:"client_id,omitempty"`
		SessionID   string         `json:"session_id,omitempty"`
		IPAddress   string         `json:"ip_address,omitempty"`
		UserAgent   string         `json:"user_agent,omitempty"`
		Outcome     string         `json:"outcome"`
		ErrorCode   string         `json:"error_code,omitempty"`
		Metadata    map[string]any `json:"metadata,omitempty"`
		CreatedAt   time.Time      `json:"created_at"`
	}
	w := wire{
		TenantID:    e.TenantID.String(),
		EventType:   e.EventType,
		ActorType:   e.ActorType,
		ActorID:     e.ActorID,
		SubjectType: e.SubjectType,
		SubjectID:   e.SubjectID,
		ClientID:    e.ClientID,
		SessionID:   e.SessionID,
		UserAgent:   e.UserAgent,
		Outcome:     e.Outcome,
		ErrorCode:   e.ErrorCode,
		Metadata:    e.Metadata,
		CreatedAt:   e.CreatedAt.UTC(),
	}
	if e.IPAddress != nil {
		w.IPAddress = e.IPAddress.String()
	}
	return json.Marshal(w)
}

func truncateErr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
