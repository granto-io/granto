package oauth2_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestLogoutClearsSessionAndRedirects(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	sess := &domain.LoginSession{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		Subject:         "user-1",
		AuthenticatedAt: time.Now().UTC(),
		ExpiresAt:       time.Now().Add(time.Hour),
		Remember:        true,
	}
	if err := d.sess.Create(ctx, sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	rtHash := domain.HashToken("rt-logout")
	if err := d.tokens.CreateRefreshToken(ctx, &domain.RefreshToken{
		TokenHash: rtHash,
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		SessionID: sess.ID,
		Scopes:    []string{"openid"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	d.clients.byID["app-a"].PostLogoutURIs = []string{"https://app.example/bye"}

	res, err := d.flow.Logout(ctx, oauth2.LogoutInput{
		SessionIDFromCookie: sess.ID.String(),
		ClientID:            "app-a",
		PostLogoutRedirect:  "https://app.example/bye",
		State:               "st-1",
	})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !res.ClearCookie {
		t.Fatal("expected ClearCookie")
	}
	if !strings.Contains(res.RedirectTo, "https://app.example/bye") || !strings.Contains(res.RedirectTo, "state=st-1") {
		t.Fatalf("RedirectTo = %q", res.RedirectTo)
	}
	if _, err := d.sess.GetByID(ctx, sess.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("session should be deleted, err=%v", err)
	}
	if _, err := d.tokens.GetRefreshToken(ctx, domain.DefaultTenantID, rtHash); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("refresh should be revoked, err=%v", err)
	}
}

func TestLogoutRejectsUnregisteredPostLogoutURI(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	d.clients.byID["app-a"].PostLogoutURIs = []string{"https://app.example/bye"}

	_, err := d.flow.Logout(ctx, oauth2.LogoutInput{
		ClientID:           "app-a",
		PostLogoutRedirect: "https://evil.example/steal",
	})
	if !errors.Is(err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}

func TestLogoutWithoutRedirectStillClearsCookie(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	sess := &domain.LoginSession{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		Subject:         "user-1",
		AuthenticatedAt: time.Now().UTC(),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := d.sess.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	res, err := d.flow.Logout(ctx, oauth2.LogoutInput{
		SessionIDFromCookie: sess.ID.String(),
	})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !res.ClearCookie || res.RedirectTo != "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestLogoutScopeDeviceDeletesSiblingSessions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	d.cfg.Session.LogoutScope = "device"

	deviceID := uuid.New().String()
	keepDevice := uuid.New().String()
	s1 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		DeviceID: deviceID, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	s2 := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		DeviceID: deviceID, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	sOther := &domain.LoginSession{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, Subject: "user-1",
		DeviceID: keepDevice, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, s := range []*domain.LoginSession{s1, s2, sOther} {
		if err := d.sess.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	_, err := d.flow.Logout(ctx, oauth2.LogoutInput{
		SessionIDFromCookie: s1.ID.String(),
		DeviceIDFromCookie:  deviceID,
	})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := d.sess.GetByID(ctx, s1.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("s1 should be gone, err=%v", err)
	}
	if _, err := d.sess.GetByID(ctx, s2.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("s2 should be gone, err=%v", err)
	}
	if _, err := d.sess.GetByID(ctx, sOther.ID); err != nil {
		t.Fatalf("other device session should remain: %v", err)
	}
}

func TestLogoutScopeSubjectDeletesAllSubjectSessions(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	d.cfg.Session.LogoutScope = "subject"

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
		DeviceID: uuid.New().String(), AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, s := range []*domain.LoginSession{s1, s2, sOther} {
		if err := d.sess.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	_, err := d.flow.Logout(ctx, oauth2.LogoutInput{SessionIDFromCookie: s1.ID.String()})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := d.sess.GetByID(ctx, s1.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatal("s1 should be gone")
	}
	if _, err := d.sess.GetByID(ctx, s2.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatal("s2 should be gone")
	}
	if _, err := d.sess.GetByID(ctx, sOther.ID); err != nil {
		t.Fatalf("other subject should remain: %v", err)
	}
}

func TestAcceptLoginCopiesDeviceID(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	deviceID := uuid.New().String()
	ch := sampleLoginChallenge(t)
	ch.DeviceID = deviceID
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create challenge: %v", err)
	}
	_, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		Subject:     "user-1",
		Remember:    true,
	})
	if err != nil {
		t.Fatalf("AcceptLogin: %v", err)
	}
	found := false
	for _, s := range d.sess.byID {
		if s.Subject == "user-1" && s.DeviceID == deviceID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session with DeviceID=%s, got %+v", deviceID, d.sess.byID)
	}
}
