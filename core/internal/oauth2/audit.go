package oauth2

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/reqmeta"
)

// audit hands the event to AuditRepository after filling tenant / IP / UA from ctx.
// With the process Bus, Log returns immediately and the outbox INSERT runs on a
// context detached from request cancellation (see audit.Bus.Log).
func (f *Flow) audit(ctx context.Context, e *domain.AuditEvent) {
	if f == nil || f.audits == nil || e == nil {
		return
	}
	if e.TenantID == uuid.Nil {
		e.TenantID = f.resolveTenant(ctx)
	}
	if e.IPAddress == nil {
		if ip := reqmeta.IP(ctx); ip != nil {
			e.IPAddress = ip
		}
	}
	if e.UserAgent == "" {
		e.UserAgent = reqmeta.UserAgent(ctx)
	}
	_ = f.audits.Log(ctx, e)
}

// auditSuccess is a shorthand for a successful audit event.
func (f *Flow) auditSuccess(ctx context.Context, eventType, actorType, actorID string, mutate func(*domain.AuditEvent)) {
	e := &domain.AuditEvent{
		TenantID:  f.resolveTenant(ctx),
		EventType: eventType,
		ActorType: actorType,
		ActorID:   actorID,
		Outcome:   domain.AuditOutcomeSuccess,
	}
	if mutate != nil {
		mutate(e)
	}
	f.audit(ctx, e)
}

// auditFailure records a failed outcome with optional error_code.
func (f *Flow) auditFailure(ctx context.Context, eventType, actorType, actorID, errCode string, mutate func(*domain.AuditEvent)) {
	e := &domain.AuditEvent{
		TenantID:  f.resolveTenant(ctx),
		EventType: eventType,
		ActorType: actorType,
		ActorID:   actorID,
		Outcome:   domain.AuditOutcomeFailure,
		ErrorCode: errCode,
	}
	if mutate != nil {
		mutate(e)
	}
	f.audit(ctx, e)
}

// auditAuthorizeFailure emits authorize_error for a failed /oauth2/auth attempt.
func (f *Flow) auditAuthorizeFailure(ctx context.Context, clientID string, err error) {
	f.auditFailure(ctx, domain.AuditEventAuthorizeError, domain.AuditActorClient, clientID, auditErrorCode(err), func(e *domain.AuditEvent) {
		e.ClientID = clientID
		e.SubjectType = domain.AuditSubjectClient
		e.SubjectID = clientID
	})
}

// auditTokenFailure emits token_error for a failed token-endpoint attempt.
func (f *Flow) auditTokenFailure(ctx context.Context, clientID, errCode string, meta map[string]any) {
	f.auditFailure(ctx, domain.AuditEventTokenError, domain.AuditActorClient, clientID, errCode, func(e *domain.AuditEvent) {
		e.ClientID = clientID
		e.SubjectType = domain.AuditSubjectClient
		e.SubjectID = clientID
		if meta != nil {
			e.Metadata = meta
		}
	})
}

// auditErrorCode maps a Flow error to an OAuth/OIDC error code string for audit.
func auditErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, ErrInvalidClient), errors.Is(err, ErrInvalidClientSecret):
		return "invalid_client"
	case errors.Is(err, ErrUnauthorizedClient):
		return "unauthorized_client"
	case errors.Is(err, ErrLoginRequired):
		return "login_required"
	case errors.Is(err, ErrConsentRequired):
		return "consent_required"
	case errors.Is(err, ErrInvalidGrant):
		return "invalid_grant"
	case errors.Is(err, ErrInvalidCodeVerifier), errors.Is(err, ErrPKCERequired):
		return "invalid_grant"
	case errors.Is(err, ErrInvalidRedirectURI):
		return "invalid_request"
	case errors.Is(err, ErrSessionExpired):
		return "invalid_grant"
	default:
		return "invalid_request"
	}
}
