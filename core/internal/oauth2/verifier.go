package oauth2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// SessionCookieName is the AS-domain SSO cookie (sid).
const SessionCookieName = "granto_sid"

// CompleteVerifierResult is returned after consuming login_verifier / consent_verifier.
type CompleteVerifierResult struct {
	SessionID  uuid.UUID
	RedirectTo string
	Remember   bool
	// CookieMaxAgeSeconds is MaxAge for Set-Cookie; 0 = session cookie.
	CookieMaxAgeSeconds int
}

// CompleteVerifier consumes a one-shot FlowVerifier and returns cookie + next redirect.
func (f *Flow) CompleteVerifier(ctx context.Context, kind domain.FlowVerifierKind, verifierID string) (*CompleteVerifierResult, error) {
	id, err := parseChallengeID(verifierID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid verifier id", ErrInvalidRequest)
	}
	v, err := f.flowVerifiers.Consume(ctx, f.tenantID(), id)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrFlowVerifierNotFound):
			return nil, ErrVerifierNotFound
		case errors.Is(err, domain.ErrFlowVerifierExpired):
			return nil, ErrVerifierExpired
		default:
			return nil, err
		}
	}
	if v.Kind != kind {
		return nil, fmt.Errorf("%w: verifier kind mismatch", ErrInvalidRequest)
	}

	out := &CompleteVerifierResult{
		SessionID:  v.SessionID,
		RedirectTo: v.RedirectTo,
	}
	if v.SessionID != uuid.Nil {
		if sess, err := f.loginSessions.GetByID(ctx, v.SessionID); err == nil && !sess.IsExpired() {
			out.Remember = sess.Remember
			if sess.Remember {
				sec := int(time.Until(sess.ExpiresAt).Seconds())
				if sec < 0 {
					sec = 0
				}
				out.CookieMaxAgeSeconds = sec
			}
		}
	}
	return out, nil
}
