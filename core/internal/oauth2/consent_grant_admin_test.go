package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestAdminListAndRevokeConsentGrants(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	g1 := &domain.ConsentGrant{
		ID: uuid.New(), TenantID: domain.DefaultTenantID,
		Subject: "user-1", ClientID: "app-a",
		Scopes: []string{"openid", "profile"}, Audience: []string{},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	g2 := &domain.ConsentGrant{
		ID: uuid.New(), TenantID: domain.DefaultTenantID,
		Subject: "user-1", ClientID: "app-b",
		Scopes: []string{"openid"}, Audience: []string{},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	gOther := &domain.ConsentGrant{
		ID: uuid.New(), TenantID: domain.DefaultTenantID,
		Subject: "user-2", ClientID: "app-a",
		Scopes: []string{"openid"}, Audience: []string{},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	for _, g := range []*domain.ConsentGrant{g1, g2, gOther} {
		if err := d.grants.Upsert(ctx, g); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	list, err := d.flow.ListConsentGrants(ctx, "user-1", "")
	if err != nil {
		t.Fatalf("ListConsentGrants: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}

	filtered, err := d.flow.ListConsentGrants(ctx, "user-1", "app-a")
	if err != nil {
		t.Fatalf("ListConsentGrants filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ClientID != "app-a" {
		t.Fatalf("filtered = %+v", filtered)
	}

	if err := d.flow.RevokeConsentGrants(ctx, "user-1", "app-a"); err != nil {
		t.Fatalf("Revoke one: %v", err)
	}
	if _, err := d.grants.Get(ctx, domain.DefaultTenantID, "user-1", "app-a"); err == nil {
		t.Fatal("app-a grant should be gone")
	}
	if _, err := d.grants.Get(ctx, domain.DefaultTenantID, "user-1", "app-b"); err != nil {
		t.Fatalf("app-b should remain: %v", err)
	}

	if err := d.flow.RevokeConsentGrants(ctx, "user-1", ""); err != nil {
		t.Fatalf("Revoke all: %v", err)
	}
	left, err := d.flow.ListConsentGrants(ctx, "user-1", "")
	if err != nil {
		t.Fatalf("List after revoke all: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("want empty, got %d", len(left))
	}
	if _, err := d.grants.Get(ctx, domain.DefaultTenantID, "user-2", "app-a"); err != nil {
		t.Fatalf("user-2 grant should remain: %v", err)
	}
}

func TestAdminListConsentGrantsRequiresSubject(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	_, err := d.flow.ListConsentGrants(t.Context(), "", "")
	if !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
	if err := d.flow.RevokeConsentGrants(t.Context(), "", "app-a"); !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}
