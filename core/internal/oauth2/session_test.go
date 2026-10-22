package oauth2_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestAdminGetListDeleteLoginSession(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	s1 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		DeviceID: uuid.New().String(), AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	s2 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		DeviceID: uuid.New().String(), AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	sOther := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-2",
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, s := range []*domain.LoginSession{s1, s2, sOther} {
		if err := d.sess.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	rtHash := domain.HashToken("rt-admin-sess")
	if err := d.tokens.CreateRefreshToken(ctx, &domain.RefreshToken{
		TokenHash: rtHash, JTI: uuid.NewString(), TenantID: domain.DefaultTenantID,
		ClientID: "app-a", Subject: "user-1", SessionID: s1.ID,
		Scopes: []string{"openid"}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got, err := d.flow.GetLoginSession(ctx, s1.ID.String())
	if err != nil {
		t.Fatalf("GetLoginSession: %v", err)
	}
	if got.Subject != "user-1" || got.ID != s1.ID {
		t.Fatalf("got %+v", got)
	}

	list, err := d.flow.ListLoginSessions(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListLoginSessions: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}

	if err := d.flow.DeleteLoginSession(ctx, s1.ID.String()); err != nil {
		t.Fatalf("DeleteLoginSession: %v", err)
	}
	if _, err := d.sess.GetByID(ctx, s1.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("session should be gone, err=%v", err)
	}
	if _, err := d.tokens.GetRefreshToken(ctx, domain.DefaultTenantID, rtHash); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("refresh should be revoked, err=%v", err)
	}
	if _, err := d.sess.GetByID(ctx, s2.ID); err != nil {
		t.Fatalf("s2 should remain: %v", err)
	}
}

func TestAdminDeleteLoginSessionsBySubject(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	s1 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	s2 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	sOther := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-2",
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, s := range []*domain.LoginSession{s1, s2, sOther} {
		if err := d.sess.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := d.flow.DeleteLoginSessionsBySubject(ctx, "user-1"); err != nil {
		t.Fatalf("DeleteLoginSessionsBySubject: %v", err)
	}
	if _, err := d.sess.GetByID(ctx, s1.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatal("s1 should be gone")
	}
	if _, err := d.sess.GetByID(ctx, s2.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatal("s2 should be gone")
	}
	if _, err := d.sess.GetByID(ctx, sOther.ID); err != nil {
		t.Fatalf("user-2 should remain: %v", err)
	}
}

func TestAdminRevokeLoginSessionsHydraStyle(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	sess := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := d.sess.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := d.flow.RevokeLoginSessions(ctx, "", ""); !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
	if err := d.flow.RevokeLoginSessions(ctx, "user-1", sess.ID.String()); !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("both subject+sid: err=%v", err)
	}
	if err := d.flow.RevokeLoginSessions(ctx, "", sess.ID.String()); err != nil {
		t.Fatalf("revoke by sid: %v", err)
	}
	if _, err := d.sess.GetByID(ctx, sess.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatal("session should be gone")
	}
}

func TestAdminGetLoginSessionNotFound(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	_, err := d.flow.GetLoginSession(t.Context(), uuid.New().String())
	if !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("err=%v, want not found", err)
	}
	_, err = d.flow.ListLoginSessions(t.Context(), "")
	if !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}
