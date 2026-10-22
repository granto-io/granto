package oauth2

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// GetLoginSession loads one AS login session by id (tenant-scoped).
func (f *Flow) GetLoginSession(ctx context.Context, id string) (*domain.LoginSession, error) {
	sid, err := parseSessionID(id)
	if err != nil {
		return nil, err
	}
	return f.requireLoginSession(ctx, sid)
}

// ListLoginSessions returns all login sessions for subject in the current tenant.
func (f *Flow) ListLoginSessions(ctx context.Context, subject string) ([]*domain.LoginSession, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrInvalidRequest)
	}
	return f.loginSessions.ListBySubject(ctx, f.resolveTenant(ctx), subject)
}

// DeleteLoginSession removes one session, notifies RPs via back-channel logout,
// and revokes its refresh tokens.
func (f *Flow) DeleteLoginSession(ctx context.Context, id string) error {
	sid, err := parseSessionID(id)
	if err != nil {
		return err
	}
	sess, err := f.requireLoginSession(ctx, sid)
	if err != nil {
		return err
	}
	f.notifyBackChannelForSession(ctx, sess)
	return f.deleteOneLoginSession(ctx, sid)
}

// DeleteLoginSessionsBySubject removes all sessions for subject and revokes
// refresh tokens for each.
func (f *Flow) DeleteLoginSessionsBySubject(ctx context.Context, subject string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return fmt.Errorf("%w: subject is required", ErrInvalidRequest)
	}
	sessions, err := f.loginSessions.ListBySubject(ctx, f.resolveTenant(ctx), subject)
	if err != nil {
		return err
	}
	for _, s := range sessions {
		f.notifyBackChannelForSession(ctx, s)
		if err := f.deleteOneLoginSession(ctx, s.ID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeLoginSessions mirrors Hydra DELETE /admin/oauth2/auth/sessions/login:
// either sid (one session) or subject (all). Exactly one must be set.
func (f *Flow) RevokeLoginSessions(ctx context.Context, subject, sid string) error {
	subject = strings.TrimSpace(subject)
	sid = strings.TrimSpace(sid)
	switch {
	case sid != "" && subject != "":
		return fmt.Errorf("%w: provide either sid or subject, not both", ErrInvalidRequest)
	case sid != "":
		return f.DeleteLoginSession(ctx, sid)
	case subject != "":
		return f.DeleteLoginSessionsBySubject(ctx, subject)
	default:
		return fmt.Errorf("%w: subject or sid is required", ErrInvalidRequest)
	}
}

func (f *Flow) requireLoginSession(ctx context.Context, id uuid.UUID) (*domain.LoginSession, error) {
	sess, err := f.loginSessions.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if sess.TenantID != f.resolveTenant(ctx) {
		return nil, domain.ErrLoginSessionNotFound
	}
	return sess, nil
}

func parseSessionID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: invalid session id", ErrInvalidRequest)
	}
	return id, nil
}
