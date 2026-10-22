package audit_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/granto-io/granto/core/internal/audit"
	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
)

type memOutbox struct {
	mu   sync.Mutex
	rows map[int64]repository.AuditOutboxRow
	next int64
}

func newMemOutbox() *memOutbox {
	return &memOutbox{rows: map[int64]repository.AuditOutboxRow{}}
}

func (m *memOutbox) Log(_ context.Context, event *domain.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	m.rows[m.next] = repository.AuditOutboxRow{
		ID:        m.next,
		Payload:   []byte(`{"event_type":"` + event.EventType + `"}`),
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

func (m *memOutbox) ClaimBatch(context.Context, int, time.Duration) ([]repository.AuditOutboxRow, error) {
	return nil, nil
}
func (m *memOutbox) Ack(context.Context, int64) error { return nil }
func (m *memOutbox) Nack(context.Context, int64, time.Duration, string) error {
	return nil
}
func (m *memOutbox) Stop() {}

func TestBusLogEnqueuesWhenEnabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Enabled:  true,
			Channels: []string{"stdout"},
			Outbox: config.AuditOutboxConfig{
				PollInterval: time.Hour, // avoid busy drain in test
				BatchSize:    10,
				MaxAttempts:  5,
			},
		},
	}
	ob := newMemOutbox()
	bus, err := audit.NewBus(cfg, ob, nil)
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	if err := bus.Log(t.Context(), &domain.AuditEvent{
		TenantID:  domain.DefaultTenantID,
		EventType: domain.AuditEventLoginAccepted,
		ActorType: domain.AuditActorAdmin,
		Outcome:   domain.AuditOutcomeSuccess,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Log: %v", err)
	}
	bus.Stop() // waits for async enqueue
	ob.mu.Lock()
	n := len(ob.rows)
	ob.mu.Unlock()
	if n != 1 {
		t.Fatalf("outbox rows=%d, want 1", n)
	}
}

func TestBusLogNoopWhenDisabled(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Audit: config.AuditConfig{Enabled: false, Channels: []string{"stdout"}}}
	ob := newMemOutbox()
	bus, err := audit.NewBus(cfg, ob, nil)
	if err != nil {
		t.Fatalf("NewBus: %v", err)
	}
	defer bus.Stop()
	_ = bus.Log(t.Context(), &domain.AuditEvent{EventType: "x"})
	ob.mu.Lock()
	n := len(ob.rows)
	ob.mu.Unlock()
	if n != 0 {
		t.Fatalf("outbox rows=%d, want 0", n)
	}
}

func TestNewBusRejectsWebhookWithoutURL(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Enabled:  true,
			Channels: []string{"webhook"},
		},
	}
	_, err := audit.NewBus(cfg, newMemOutbox(), nil)
	if err == nil {
		t.Fatal("expected error for missing webhook.url")
	}
}
