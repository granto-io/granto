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

func baseAuthorizeInput() oauth2.AuthorizeInput {
	return oauth2.AuthorizeInput{
		ClientID:            "app-a",
		ResponseType:        "code",
		RedirectURI:         "https://app.example/cb",
		Scope:               "openid",
		State:               "st",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		RequestURL:          "https://auth.example/oauth2/auth",
	}
}

func createSSOSession(t *testing.T, d *testDeps) *domain.LoginSession {
	t.Helper()
	sess := &domain.LoginSession{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		Subject:         "user-1",
		AuthenticatedAt: time.Now().UTC().Add(-time.Hour),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := d.sess.Create(t.Context(), sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	return sess
}

func TestAuthorizePromptNoneWithoutSession(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	in := baseAuthorizeInput()
	in.Prompt = "none"
	_, err := d.flow.Authorize(t.Context(), in)
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrLoginRequired) {
		t.Fatalf("err=%v, want ClientRedirectError login_required", err)
	}
}

func TestAuthorizePromptLoginForcesReauth(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	d.clients.byID["app-a"].SkipConsent = true
	sess := createSSOSession(t, d)

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.Prompt = "login"
	res, err := d.flow.Authorize(t.Context(), in)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.Contains(res.RedirectTo, "login_challenge=") {
		t.Fatalf("RedirectTo = %q, want login_challenge", res.RedirectTo)
	}
	if len(d.login.byID) != 1 {
		t.Fatalf("login challenges = %d", len(d.login.byID))
	}
	for _, ch := range d.login.byID {
		if ch.SessionID != uuid.Nil {
			t.Fatalf("SessionID should be nil on forced login, got %s", ch.SessionID)
		}
	}
}

func TestAuthorizeMaxAgeForcesReauth(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	d.clients.byID["app-a"].SkipConsent = true
	sess := createSSOSession(t, d) // AuthenticatedAt = now-1h

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.MaxAge = "60" // 1 minute < 1 hour ago
	res, err := d.flow.Authorize(t.Context(), in)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.Contains(res.RedirectTo, "login_challenge=") {
		t.Fatalf("RedirectTo = %q, want login_challenge", res.RedirectTo)
	}
}

func TestAuthorizePromptNoneMaxAgeExceeded(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	sess := createSSOSession(t, d)

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.Prompt = "none"
	in.MaxAge = "1"
	_, err := d.flow.Authorize(t.Context(), in)
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrLoginRequired) {
		t.Fatalf("err=%v, want login_required", err)
	}
}

func TestAuthorizePromptConsentForcesConsentUI(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	d.clients.byID["app-a"].SkipConsent = true
	sess := createSSOSession(t, d)

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.Prompt = "consent"
	res, err := d.flow.Authorize(t.Context(), in)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.Contains(res.RedirectTo, "consent_challenge=") {
		t.Fatalf("RedirectTo = %q, want consent_challenge", res.RedirectTo)
	}
	if len(d.consent.byID) != 1 {
		t.Fatalf("consent challenges = %d", len(d.consent.byID))
	}
}

func TestAuthorizePromptNoneConsentRequired(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	// app-a has no SkipConsent; no grant → consent needed
	sess := createSSOSession(t, d)

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.Prompt = "none"
	_, err := d.flow.Authorize(t.Context(), in)
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrConsentRequired) {
		t.Fatalf("err=%v, want consent_required", err)
	}
}

func TestAuthorizePromptNoneWithSkipConsentOK(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	d.clients.byID["app-a"].SkipConsent = true
	sess := createSSOSession(t, d)

	in := baseAuthorizeInput()
	in.ExistingSessionID = sess.ID.String()
	in.Prompt = "none"
	res, err := d.flow.Authorize(t.Context(), in)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.Contains(res.RedirectTo, "consent_verifier=") {
		t.Fatalf("RedirectTo = %q, want consent_verifier", res.RedirectTo)
	}
}

func TestAuthorizePromptNoneCombinedInvalid(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	in := baseAuthorizeInput()
	in.Prompt = "none login"
	_, err := d.flow.Authorize(t.Context(), in)
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}

func TestAuthorizeInvalidMaxAge(t *testing.T) {
	t.Parallel()
	d := newTestFlow(t, false)
	in := baseAuthorizeInput()
	in.MaxAge = "nope"
	_, err := d.flow.Authorize(t.Context(), in)
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrInvalidRequest) {
		t.Fatalf("err=%v, want invalid_request", err)
	}
}
