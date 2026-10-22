package repository

import (
	"context"
	"time"

	"github.com/granto-io/granto/core/internal/domain"
)

// AuditRepository accepts audit events for delivery to configured channels.
// Implemented by audit.Bus (outbox + dispatcher). Stop shuts down delivery.
type AuditRepository interface {
	Log(ctx context.Context, event *domain.AuditEvent) error
	Stop()
}

// AuditOutbox is the durable buffer behind audit.Bus.
type AuditOutbox interface {
	Log(ctx context.Context, event *domain.AuditEvent) error
	ClaimBatch(ctx context.Context, limit int, lease time.Duration) ([]AuditOutboxRow, error)
	Ack(ctx context.Context, id int64) error
	Nack(ctx context.Context, id int64, backoff time.Duration, lastErr string) error
	Stop()
}

// AuditOutboxRow is one claimed outbox record.
type AuditOutboxRow struct {
	ID        int64
	Payload   []byte
	CreatedAt time.Time
	Attempts  int
}
