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
	return f.consentGrants.ListBySubject(ctx, f.tenantID(), subject, strings.TrimSpace(clientID))
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
	if clientID != "" {
		return f.consentGrants.Delete(ctx, f.tenantID(), subject, clientID)
	}
	return f.consentGrants.DeleteBySubject(ctx, f.tenantID(), subject)
}
