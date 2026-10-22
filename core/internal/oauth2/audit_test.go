package oauth2_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
)

type memAudit struct {
	mu     sync.Mutex
	events []*domain.AuditEvent
}

func (m *memAudit) Log(_ context.Context, e *domain.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *e
	if e.Metadata != nil {
		cp.Metadata = map[string]any{}
		for k, v := range e.Metadata {
			cp.Metadata[k] = v
		}
	}
	m.events = append(m.events, &cp)
	return nil
}
func (m *memAudit) Stop() {}

func (m *memAudit) types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events))
	for _, e := range m.events {
		out = append(out, e.EventType)
	}
	return out
}

func (m *memAudit) lastOf(eventType string) *domain.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].EventType == eventType {
			return m.events[i]
		}
	}
	return nil
}

func withAudit(t *testing.T, d *testDeps) *memAudit {
	t.Helper()
	aud := &memAudit{}
	d.flow = oauth2.NewFlow(
		d.cfg, d.clients, d.login, d.consent, d.sess, &memVerifiers{},
		d.codes, d.tokens, d.grants, nil, aud,
	)
	return aud
}

func TestAcceptLoginWritesAuditEvents(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	aud := withAudit(t, d)

	ch := &domain.LoginChallenge{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		ClientID:        "app-a",
		RedirectURI:     "https://app.example/cb",
		State:           "st",
		ResponseType:    "code",
		RequestedScopes: []string{"openid"},
		ExpiresAt:       time.Now().Add(time.Hour),
		CreatedAt:       time.Now().UTC(),
	}
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create challenge: %v", err)
	}

	if _, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		AcceptToken: ch.AcceptToken,
		Subject:     "user-1",
	}); err != nil {
		t.Fatalf("AcceptLogin: %v", err)
	}

	got := aud.types()
	wantLogin, wantSession := false, false
	for _, typ := range got {
		if typ == domain.AuditEventLoginAccepted {
			wantLogin = true
		}
		if typ == domain.AuditEventSessionCreated {
			wantSession = true
		}
	}
	if !wantLogin || !wantSession {
		t.Fatalf("audit types=%v, want login_accepted and session_created", got)
	}
}

func TestRejectLoginWritesFailureAudit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	aud := withAudit(t, d)

	ch := &domain.LoginChallenge{
		ID:           uuid.New(),
		TenantID:     domain.DefaultTenantID,
		ClientID:     "app-a",
		RedirectURI:  "https://app.example/cb",
		State:        "st",
		ResponseType: "code",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now().UTC(),
	}
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := d.flow.RejectLogin(ctx, oauth2.RejectInput{
		ChallengeID: ch.ID.String(),
		Error:       "access_denied",
	}); err != nil {
		t.Fatalf("RejectLogin: %v", err)
	}
	e := aud.lastOf(domain.AuditEventLoginRejected)
	if e == nil {
		t.Fatalf("missing login_rejected; types=%v", aud.types())
	}
	if e.Outcome != domain.AuditOutcomeFailure {
		t.Fatalf("Outcome=%q, want failure", e.Outcome)
	}
	if e.ErrorCode != "access_denied" {
		t.Fatalf("ErrorCode=%q, want access_denied", e.ErrorCode)
	}
}

func TestBadClientSecretWritesTokenErrorAudit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	aud := withAudit(t, d)

	hash, err := bcrypt.GenerateFromPassword([]byte("real"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	d.clients.byID["conf"] = &domain.Client{
		ClientID:                "conf",
		TenantID:                domain.DefaultTenantID,
		ClientType:              domain.ClientTypeConfidential,
		ClientSecretHash:        string(hash),
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretPost,
		GrantTypes:              []domain.GrantType{domain.GrantTypeClientCredentials},
		AllowedScopes:           []string{"api"},
		DefaultScopes:           []string{"api"},
	}
	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "conf",
		ClientSecret: "wrong",
	})
	if !errors.Is(err, oauth2.ErrInvalidClientSecret) {
		t.Fatalf("err=%v, want ErrInvalidClientSecret", err)
	}
	e := aud.lastOf(domain.AuditEventTokenError)
	if e == nil {
		t.Fatalf("missing token_error; types=%v", aud.types())
	}
	if e.Outcome != domain.AuditOutcomeFailure || e.ErrorCode != "invalid_client" {
		t.Fatalf("event=%+v", e)
	}
	if e.Metadata["reason"] != "bad_client_secret" {
		t.Fatalf("reason=%v", e.Metadata["reason"])
	}
}

func TestCodeReplayWritesTokenErrorAudit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	aud := withAudit(t, d)

	secret := "code-client-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	d.clients.byID["conf-code"] = &domain.Client{
		ClientID:                "conf-code",
		TenantID:                domain.DefaultTenantID,
		ClientType:              domain.ClientTypeConfidential,
		ClientSecretHash:        string(hash),
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretPost,
		GrantTypes: []domain.GrantType{
			domain.GrantTypeAuthorizationCode,
			domain.GrantTypeRefreshToken,
		},
		RedirectURIs:  []string{"https://app.example/cb"},
		AllowedScopes: []string{"openid"},
	}

	raw := "auth-code-raw"
	code := &domain.AuthorizationCode{
		CodeHash:    domain.HashAuthorizationCode(raw),
		TenantID:    domain.DefaultTenantID,
		ClientID:    "conf-code",
		Subject:     "user-1",
		RedirectURI: "https://app.example/cb",
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().Add(time.Hour),
		CreatedAt:   time.Now().UTC(),
	}
	if err := d.codes.Create(ctx, code); err != nil {
		t.Fatalf("Create code: %v", err)
	}
	in := oauth2.ExchangeCodeInput{
		ClientID:     "conf-code",
		ClientSecret: secret,
		Code:         raw,
		RedirectURI:  "https://app.example/cb",
	}
	if _, err := d.flow.ExchangeCode(ctx, in); err != nil {
		t.Fatalf("first ExchangeCode: %v", err)
	}
	_, err = d.flow.ExchangeCode(ctx, in)
	if !errors.Is(err, oauth2.ErrInvalidGrant) {
		t.Fatalf("replay err=%v, want ErrInvalidGrant", err)
	}
	e := aud.lastOf(domain.AuditEventTokenError)
	if e == nil {
		t.Fatalf("missing token_error; types=%v", aud.types())
	}
	if e.Metadata["reason"] != "code_replay" {
		t.Fatalf("reason=%v, want code_replay", e.Metadata["reason"])
	}
}

func TestAuthorizeErrorWritesAudit(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := newTestFlow(t, false)
	aud := withAudit(t, d)

	_, err := d.flow.Authorize(ctx, oauth2.AuthorizeInput{
		ClientID:     "app-a",
		ResponseType: "code",
		RedirectURI:  "https://app.example/cb",
		Scope:        "not-allowed-scope",
		State:        "st",
	})
	var cre *oauth2.ClientRedirectError
	if !errors.As(err, &cre) || !errors.Is(cre.Err, oauth2.ErrInvalidScope) {
		t.Fatalf("err=%v, want ClientRedirectError(invalid_scope)", err)
	}
	e := aud.lastOf(domain.AuditEventAuthorizeError)
	if e == nil {
		t.Fatalf("missing authorize_error; types=%v", aud.types())
	}
	if e.Outcome != domain.AuditOutcomeFailure || e.ErrorCode != "invalid_scope" {
		t.Fatalf("event=%+v", e)
	}
}
