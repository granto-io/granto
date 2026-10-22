package admin

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/granto-io/granto/core/internal/domain"
)

type tenantCtxKey struct{}

// WithTenantID attaches the authenticated Admin tenant to ctx.
func WithTenantID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenantID)
}

// TenantIDFromContext returns the Admin tenant bound by the auth interceptor.
func TenantIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(tenantCtxKey{}).(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.Nil, false
	}
	return id, true
}

// authTenantID is the tenant of the authenticated Admin caller.
// MVP: always DefaultTenantID until Admin tokens carry a tenant claim.
func authTenantID(ctx context.Context) uuid.UUID {
	if id, ok := TenantIDFromContext(ctx); ok {
		return id
	}
	// Defensive fallback (unit tests without interceptor).
	return domain.DefaultTenantID
}

// resolveRequestTenant binds Create/List to the authenticated tenant.
// A non-empty request tenant_id that differs from the auth tenant is rejected
// (clients must not pick an arbitrary tenant from the body/query).
func resolveRequestTenant(ctx context.Context, requested string) (uuid.UUID, error) {
	auth := authTenantID(ctx)
	if requested == "" {
		return auth, nil
	}
	reqID, err := uuid.Parse(requested)
	if err != nil {
		return uuid.Nil, status.Error(codes.InvalidArgument, "tenant_id must be a UUID")
	}
	if reqID != auth {
		return uuid.Nil, status.Error(codes.PermissionDenied, "tenant_id does not match authenticated tenant")
	}
	return auth, nil
}
