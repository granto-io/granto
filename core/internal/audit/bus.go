package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/repository"
	"github.com/granto-io/granto/core/internal/reqmeta"
)

// Bus enqueues audit events into the durable outbox and delivers them to channels.
type Bus struct {
	repo     repository.AuditOutbox
	channels []Channel
	logger   *slog.Logger
	cfg      config.AuditConfig

	cancel context.CancelFunc
	wg     sync.WaitGroup // dispatcher loop

	logMu   sync.Mutex
	logWG   sync.WaitGroup // in-flight async outbox inserts
	stopped bool
}

// NewBus builds channels from config and starts the outbox dispatcher when enabled.
func NewBus(cfg *config.Config, repo repository.AuditOutbox, logger *slog.Logger) (*Bus, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		return &Bus{logger: logger}, nil
	}
	ac := cfg.Audit
	b := &Bus{
		repo:   repo,
		logger: logger,
		cfg:    ac,
	}
	if !ac.Enabled {
		return b, nil
	}
	channels, err := buildChannels(ac, logger)
	if err != nil {
		return nil, err
	}
	b.channels = channels
	if len(b.channels) == 0 || repo == nil {
		logger.Warn("audit enabled but no channels or outbox; events will be dropped")
		return b, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	b.wg.Add(1)
	go b.loop(ctx)
	return b, nil
}

// Log schedules an asynchronous outbox insert and returns without waiting for Postgres.
// IP / User-Agent are copied from ctx when missing on the event. The insert runs on
// context.WithoutCancel(ctx) so request cancellation after the HTTP/gRPC response
// does not drop the event. Callers must not mutate event after Log returns.
func (b *Bus) Log(ctx context.Context, event *domain.AuditEvent) error {
	if b == nil || !b.cfg.Enabled || b.repo == nil || len(b.channels) == 0 || event == nil {
		return nil
	}
	if event.IPAddress == nil {
		if ip := reqmeta.IP(ctx); ip != nil {
			event.IPAddress = ip
		}
	}
	if event.UserAgent == "" {
		event.UserAgent = reqmeta.UserAgent(ctx)
	}

	e := cloneAuditEvent(event)
	detached := context.WithoutCancel(ctx)

	b.logMu.Lock()
	if b.stopped {
		b.logMu.Unlock()
		return nil
	}
	b.logWG.Add(1)
	b.logMu.Unlock()

	go func() {
		defer b.logWG.Done()
		if err := b.repo.Log(detached, e); err != nil {
			b.logger.Error("audit outbox enqueue",
				"err", err,
				"event_type", e.EventType,
			)
		}
	}()
	return nil
}

// Stop stops accepting new Log calls, waits for in-flight enqueues and the
// dispatcher, then stops the outbox repository.
func (b *Bus) Stop() {
	if b == nil {
		return
	}
	b.logMu.Lock()
	b.stopped = true
	b.logMu.Unlock()

	b.logWG.Wait()
	if b.cancel != nil {
		b.cancel()
	}
	b.wg.Wait()
	if b.repo != nil {
		b.repo.Stop()
	}
}

func cloneAuditEvent(e *domain.AuditEvent) *domain.AuditEvent {
	if e == nil {
		return nil
	}
	cp := *e
	if e.IPAddress != nil {
		cp.IPAddress = append(net.IP(nil), e.IPAddress...)
	}
	if e.Metadata != nil {
		cp.Metadata = make(map[string]any, len(e.Metadata))
		for k, v := range e.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func (b *Bus) loop(ctx context.Context) {
	defer b.wg.Done()
	interval := b.cfg.Outbox.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.drain(ctx)
		}
	}
}

func (b *Bus) drain(ctx context.Context) {
	batch := b.cfg.Outbox.BatchSize
	if batch <= 0 {
		batch = 50
	}
	lease := b.cfg.Outbox.ClaimLease
	if lease <= 0 {
		lease = 30 * time.Second
	}
	rows, err := b.repo.ClaimBatch(ctx, batch, lease)
	if err != nil {
		b.logger.Error("audit outbox claim", "err", err)
		return
	}
	maxAttempts := b.cfg.Outbox.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	for _, row := range rows {
		if err := b.deliver(ctx, row.Payload); err != nil {
			if row.Attempts >= maxAttempts {
				b.logger.Error("audit outbox giving up",
					"id", row.ID,
					"attempts", row.Attempts,
					"err", err,
				)
				_ = b.repo.Ack(ctx, row.ID)
				continue
			}
			_ = b.repo.Nack(ctx, row.ID, backoffFor(row.Attempts), err.Error())
			continue
		}
		if err := b.repo.Ack(ctx, row.ID); err != nil {
			b.logger.Error("audit outbox ack", "id", row.ID, "err", err)
		}
	}
}

func (b *Bus) deliver(ctx context.Context, payload []byte) error {
	var first error
	for _, ch := range b.channels {
		if err := ch.Send(ctx, payload); err != nil {
			b.logger.Warn("audit channel send failed", "channel", ch.Name(), "err", err)
			if first == nil {
				first = fmt.Errorf("%s: %w", ch.Name(), err)
			}
		}
	}
	return first
}

func buildChannels(ac config.AuditConfig, logger *slog.Logger) ([]Channel, error) {
	var out []Channel
	for _, raw := range ac.Channels {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "stdout":
			out = append(out, NewStdoutChannel())
		case "webhook":
			url := strings.TrimSpace(ac.Webhook.URL)
			if url == "" {
				return nil, fmt.Errorf("audit.webhook.url is required when channels includes webhook")
			}
			out = append(out, NewWebhookChannel(url, ac.Webhook.Timeout, logger))
		case "":
			continue
		default:
			return nil, fmt.Errorf("audit.channels: unknown channel %q (want stdout or webhook)", raw)
		}
	}
	return out, nil
}

func backoffFor(attempts int) time.Duration {
	d := time.Duration(1<<min(attempts, 8)) * time.Second
	if d > 5*time.Minute {
		return 5 * time.Minute
	}
	if d < 2*time.Second {
		return 2 * time.Second
	}
	return d
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
