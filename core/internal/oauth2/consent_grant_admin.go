package oauth2

import (
	"context"
	"fmt"
	"strings"

	"github.com/granto-io/granto/core/internal/domain"
)

// ListConsentGrants returns remembered consents for subject (optional client filter).
func (f *Flow) ListConsentGrants(ctx context.Context, subject, clientID string) ([]*domain.ConsentGrant, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrInvalidRequest)
	}
	if f.consentGrants == nil {
		return nil, nil
	}
	return f.consentGrants.ListBySubject(ctx, f.resolveTenant(ctx), subject, strings.TrimSpace(clientID))
}

// RevokeConsentGrants deletes remembered consent for subject, optionally limited
// to one client_id. Empty client_id revokes all grants for the subject.
func (f *Flow) RevokeConsentGrants(ctx context.Context, subject, clientID string) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return fmt.Errorf("%w: subject is required", ErrInvalidRequest)
	}
	if f.consentGrants == nil {
		return nil
	}
	clientID = strings.TrimSpace(clientID)
	tenantID := f.resolveTenant(ctx)
	var err error
	if clientID != "" {
		err = f.consentGrants.Delete(ctx, tenantID, subject, clientID)
	} else {
		err = f.consentGrants.DeleteBySubject(ctx, tenantID, subject)
	}
	if err != nil {
		return err
	}
	f.auditSuccess(ctx, domain.AuditEventConsentGrantRevoked, domain.AuditActorAdmin, subject, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectUser
		e.SubjectID = subject
		e.ClientID = clientID
	})
	return nil
}
