package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Channel delivers a serialized audit event payload (JSON).
type Channel interface {
	Name() string
	Send(ctx context.Context, payload []byte) error
}

// StdoutChannel writes one JSON object per line to stdout.
type StdoutChannel struct {
	w io.Writer
}

// NewStdoutChannel returns a channel that writes to os.Stdout.
func NewStdoutChannel() *StdoutChannel {
	return &StdoutChannel{w: os.Stdout}
}

func (c *StdoutChannel) Name() string { return "stdout" }

func (c *StdoutChannel) Send(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w := c.w
	if w == nil {
		w = os.Stdout
	}
	_, err := fmt.Fprintf(w, "%s\n", payload)
	return err
}

// WebhookChannel POSTs the JSON payload to a configured URL.
type WebhookChannel struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

// NewWebhookChannel constructs an HTTP webhook channel.
func NewWebhookChannel(url string, timeout time.Duration, logger *slog.Logger) *WebhookChannel {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookChannel{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

func (c *WebhookChannel) Name() string { return "webhook" }

func (c *WebhookChannel) Send(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return nil
}
