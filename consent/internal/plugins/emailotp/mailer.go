package emailotp

import (
	"context"
	"log/slog"
)

// Mailer delivers login codes.
type Mailer interface {
	SendLoginCode(ctx context.Context, to, code string) error
}

// logMailer is the development delivery stub.
type logMailer struct {
	logger   *slog.Logger
	logCodes bool
}

func newLogMailer(logger *slog.Logger, logCodes bool) *logMailer {
	return &logMailer{logger: logger, logCodes: logCodes}
}

func (m *logMailer) SendLoginCode(ctx context.Context, to, code string) error {
	if m.logCodes {
		// Explicit opt-in only; codes are credentials and must not leak into
		// production logs.
		m.logger.WarnContext(ctx, "email OTP code (dev delivery stub)", "to", to, "code", code)
		return nil
	}
	m.logger.InfoContext(ctx, "email OTP code generated; delivery stub is not configured")
	return nil
}
