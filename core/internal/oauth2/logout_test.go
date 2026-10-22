package oauth2_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/keys"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/oidc"
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

func TestLogoutFrontAndBackChannel(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	d.cfg.Token.SigningKeys = config.SigningKeysConfig{
		PrivateKeyPEM: string(pemBytes),
		KID:           "test-kid",
	}
	keyMgr, err := keys.NewManager(ctx, d.cfg, nil, nil)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	d.flow = oauth2.NewFlow(
		d.cfg, d.clients, d.login, d.consent, d.sess, &memVerifiers{},
		d.codes, d.tokens, d.grants, oidc.NewIDTokens(d.cfg, keyMgr),
	)

	var (
		mu       sync.Mutex
		gotToken string
		gotCalls int
		wg       sync.WaitGroup
	)
	wg.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		_ = r.ParseForm()
		mu.Lock()
		gotCalls++
		gotToken = r.FormValue("logout_token")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	d.flow.SetHTTPClient(srv.Client())

	sess := &domain.LoginSession{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		Subject:         "user-1",
		AuthenticatedAt: time.Now().UTC(),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := d.sess.Create(ctx, sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	d.clients.byID["app-a"].FrontChannelLogoutURI = "https://app.example/front-logout"
	d.clients.byID["app-a"].BackChannelLogoutURI = srv.URL

	if err := d.tokens.CreateAccessToken(ctx, &domain.AccessToken{
		TokenHash: domain.HashToken("at-ch"),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		SessionID: sess.ID,
		Scopes:    []string{"openid"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	res, err := d.flow.Logout(ctx, oauth2.LogoutInput{
		SessionIDFromCookie: sess.ID.String(),
	})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if len(res.FrontChannelLogoutURLs) != 1 {
		t.Fatalf("FrontChannelLogoutURLs = %#v", res.FrontChannelLogoutURLs)
	}
	front := res.FrontChannelLogoutURLs[0]
	if !strings.Contains(front, "https://app.example/front-logout") ||
		!strings.Contains(front, "iss=") ||
		!strings.Contains(front, "sid="+sess.ID.String()) {
		t.Fatalf("front URL = %q", front)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for back-channel POST")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotCalls != 1 || gotToken == "" {
		t.Fatalf("back-channel calls=%d token empty=%v", gotCalls, gotToken == "")
	}
	tok, err := jwt.Parse(gotToken, func(token *jwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("parse logout_token: %v", err)
	}
	claims := tok.Claims.(jwt.MapClaims)
	if claims["sub"] != "user-1" || claims["sid"] != sess.ID.String() || claims["aud"] != "app-a" {
		t.Fatalf("logout_token claims = %#v", claims)
	}
	if _, err := d.sess.GetByID(ctx, sess.ID); !errors.Is(err, domain.ErrLoginSessionNotFound) {
		t.Fatalf("session should be deleted, err=%v", err)
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
