package tenancy

import (
	"context"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

type ctxKey struct{}

// WithID attaches the authenticated Admin tenant to ctx (D-034).
func WithID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKey{}, tenantID)
}

// FromContext returns the Admin tenant bound by the auth interceptor.
func FromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(ctxKey{}).(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}

// Resolve returns the Admin tenant from ctx, or DefaultTenantID when unbound
// (public OAuth paths / unit tests without the interceptor).
func Resolve(ctx context.Context) uuid.UUID {
	if id, ok := FromContext(ctx); ok {
		return id
	}
	return domain.DefaultTenantID
}
