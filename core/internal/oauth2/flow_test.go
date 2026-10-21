package oauth2_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/repository"
)

type memLoginChallenges struct {
	byID map[uuid.UUID]*domain.LoginChallenge
}

func (m *memLoginChallenges) Create(_ context.Context, c *domain.LoginChallenge) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.AcceptToken == "" {
		tok, err := domain.NewAcceptToken()
		if err != nil {
			return err
		}
		c.AcceptToken = tok
	}
	if m.byID == nil {
		m.byID = map[uuid.UUID]*domain.LoginChallenge{}
	}
	cp := *c
	m.byID[c.ID] = &cp
	return nil
}

func (m *memLoginChallenges) Get(_ context.Context, _, id uuid.UUID) (*domain.LoginChallenge, error) {
	c, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if c.IsExpired() {
		return nil, domain.ErrLoginChallengeExpired
	}
	cp := *c
	return &cp, nil
}

func (m *memLoginChallenges) Consume(_ context.Context, _, id uuid.UUID, opts repository.ChallengeConsumeOpts) (*domain.LoginChallenge, error) {
	c, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrLoginChallengeNotFound
	}
	if c.IsExpired() {
		return nil, domain.ErrLoginChallengeExpired
	}
	if opts.RequireToken || opts.AcceptToken != "" {
		if !c.ValidAcceptToken(opts.AcceptToken) {
			return nil, domain.ErrLoginChallengeAcceptTokenInvalid
		}
	}
	delete(m.byID, id)
	cp := *c
	return &cp, nil
}

func (m *memLoginChallenges) Delete(_ context.Context, _, id uuid.UUID) error {
	if _, ok := m.byID[id]; !ok {
		return domain.ErrLoginChallengeNotFound
	}
	delete(m.byID, id)
	return nil
}

type memConsentChallenges struct {
	byID map[uuid.UUID]*domain.ConsentChallenge
}

func (m *memConsentChallenges) Create(_ context.Context, c *domain.ConsentChallenge) error {
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.AcceptToken == "" {
		tok, err := domain.NewAcceptToken()
		if err != nil {
			return err
		}
		c.AcceptToken = tok
	}
	if m.byID == nil {
		m.byID = map[uuid.UUID]*domain.ConsentChallenge{}
	}
	cp := *c
	m.byID[c.ID] = &cp
	return nil
}

func (m *memConsentChallenges) Get(_ context.Context, _, id uuid.UUID) (*domain.ConsentChallenge, error) {
	c, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrConsentChallengeNotFound
	}
	if c.IsExpired() {
		return nil, domain.ErrConsentChallengeExpired
	}
	cp := *c
	return &cp, nil
}

func (m *memConsentChallenges) Consume(_ context.Context, _, id uuid.UUID, opts repository.ChallengeConsumeOpts) (*domain.ConsentChallenge, error) {
	c, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrConsentChallengeNotFound
	}
	if c.IsExpired() {
		return nil, domain.ErrConsentChallengeExpired
	}
	if opts.RequireToken || opts.AcceptToken != "" {
		if !c.ValidAcceptToken(opts.AcceptToken) {
			return nil, domain.ErrConsentChallengeAcceptTokenInvalid
		}
	}
	delete(m.byID, id)
	cp := *c
	return &cp, nil
}

func (m *memConsentChallenges) Delete(_ context.Context, _, id uuid.UUID) error {
	if _, ok := m.byID[id]; !ok {
		return domain.ErrConsentChallengeNotFound
	}
	delete(m.byID, id)
	return nil
}

type memSessions struct {
	byID map[uuid.UUID]*domain.LoginSession
}

func (m *memSessions) Create(_ context.Context, s *domain.LoginSession) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if m.byID == nil {
		m.byID = map[uuid.UUID]*domain.LoginSession{}
	}
	cp := *s
	m.byID[s.ID] = &cp
	return nil
}

func (m *memSessions) GetByID(_ context.Context, id uuid.UUID) (*domain.LoginSession, error) {
	s, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrLoginSessionNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *memSessions) ListBySubject(context.Context, uuid.UUID, string) ([]*domain.LoginSession, error) {
	return nil, nil
}
func (m *memSessions) Delete(context.Context, uuid.UUID) error { return nil }
func (m *memSessions) DeleteBySubject(context.Context, uuid.UUID, string) error {
	return nil
}

type memVerifiers struct {
	byID map[uuid.UUID]*domain.FlowVerifier
}

func (m *memVerifiers) Create(_ context.Context, v *domain.FlowVerifier) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	if m.byID == nil {
		m.byID = map[uuid.UUID]*domain.FlowVerifier{}
	}
	cp := *v
	m.byID[v.ID] = &cp
	return nil
}

func (m *memVerifiers) Consume(_ context.Context, _, id uuid.UUID) (*domain.FlowVerifier, error) {
	v, ok := m.byID[id]
	if !ok {
		return nil, domain.ErrFlowVerifierNotFound
	}
	delete(m.byID, id)
	cp := *v
	return &cp, nil
}

type memCodes struct {
	byHash map[string]*domain.AuthorizationCode
	used   map[string]struct{}
}

func (m *memCodes) Create(_ context.Context, c *domain.AuthorizationCode) error {
	if m.byHash == nil {
		m.byHash = map[string]*domain.AuthorizationCode{}
	}
	cp := *c
	m.byHash[c.CodeHash] = &cp
	return nil
}

func (m *memCodes) Consume(_ context.Context, _ uuid.UUID, codeHash string) (*domain.AuthorizationCode, error) {
	if m.used != nil {
		if _, ok := m.used[codeHash]; ok {
			return nil, domain.ErrAuthorizationCodeUsed
		}
	}
	c, ok := m.byHash[codeHash]
	if !ok {
		return nil, domain.ErrAuthorizationCodeNotFound
	}
	if c.IsExpired() {
		return nil, domain.ErrAuthorizationCodeExpired
	}
	delete(m.byHash, codeHash)
	if m.used == nil {
		m.used = map[string]struct{}{}
	}
	m.used[codeHash] = struct{}{}
	cp := *c
	return &cp, nil
}

type memClients struct {
	byID map[string]*domain.Client
}

func (m *memClients) GetByClientID(_ context.Context, _ uuid.UUID, clientID string) (*domain.Client, error) {
	c, ok := m.byID[clientID]
	if !ok {
		return nil, domain.ErrClientNotFound
	}
	cp := *c
	return &cp, nil
}
func (m *memClients) GetByID(context.Context, uuid.UUID) (*domain.Client, error) {
	return nil, domain.ErrClientNotFound
}
func (m *memClients) List(context.Context, uuid.UUID, repository.ClientFilter) ([]*domain.Client, error) {
	return nil, nil
}
func (m *memClients) Create(context.Context, *domain.Client) error { return nil }
func (m *memClients) Update(context.Context, *domain.Client) error { return nil }
func (m *memClients) Delete(context.Context, uuid.UUID) error      { return nil }

type memGrants struct {
	byKey map[string]*domain.ConsentGrant
}

func grantKey(subject, clientID string) string { return subject + "\x00" + clientID }

func (m *memGrants) Upsert(_ context.Context, g *domain.ConsentGrant) error {
	if m.byKey == nil {
		m.byKey = map[string]*domain.ConsentGrant{}
	}
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	cp := *g
	if cp.Scopes != nil {
		cp.Scopes = append([]string(nil), g.Scopes...)
	}
	m.byKey[grantKey(g.Subject, g.ClientID)] = &cp
	return nil
}
func (m *memGrants) Get(_ context.Context, _ uuid.UUID, subject, clientID string) (*domain.ConsentGrant, error) {
	g, ok := m.byKey[grantKey(subject, clientID)]
	if !ok || g.IsExpired() {
		return nil, domain.ErrConsentGrantNotFound
	}
	cp := *g
	return &cp, nil
}
func (m *memGrants) Delete(_ context.Context, _ uuid.UUID, subject, clientID string) error {
	delete(m.byKey, grantKey(subject, clientID))
	return nil
}

type testDeps struct {
	flow    *oauth2.Flow
	login   *memLoginChallenges
	consent *memConsentChallenges
	clients *memClients
	codes   *memCodes
	tokens  *memTokens
	sess    *memSessions
	grants  *memGrants
}

func newTestFlow(t *testing.T, strict bool) *testDeps {
	t.Helper()
	cfg := &config.Config{
		Token: config.TokenConfig{
			Issuer:          "https://auth.example",
			AccessTokenTTL:  time.Hour,
			RefreshTokenTTL: 24 * time.Hour,
		},
		OAuth2: config.OAuth2Config{
			LoginURL:   "https://consent.example/login",
			ConsentURL: "https://consent.example/consent",
		},
		Session: config.SessionConfig{
			DefaultTTL: 24 * time.Hour,
			MaxTTL:     720 * time.Hour,
		},
		Admin: config.AdminConfig{AcceptStrict: strict},
	}
	d := &testDeps{
		login:   &memLoginChallenges{},
		consent: &memConsentChallenges{},
		codes:   &memCodes{},
		tokens:  &memTokens{},
		sess:    &memSessions{},
		grants:  &memGrants{},
		clients: &memClients{byID: map[string]*domain.Client{
			"app-a": {
				ClientID:      "app-a",
				TenantID:      domain.DefaultTenantID,
				ClientType:    domain.ClientTypePublic,
				GrantTypes:    []domain.GrantType{domain.GrantTypeAuthorizationCode, domain.GrantTypeRefreshToken},
				RedirectURIs:  []string{"https://app.example/cb"},
				AllowedScopes: []string{"openid", "profile", "offline_access"},
				DefaultScopes: []string{"openid"},
				RequirePKCE:   true,
			},
		}},
	}
	d.flow = oauth2.NewFlow(cfg, d.clients, d.login, d.consent, d.sess, &memVerifiers{}, d.codes, d.tokens, d.grants, nil)
	return d
}

type memTokens struct {
	at map[string]*domain.AccessToken
	rt map[string]*domain.RefreshToken
}

func (m *memTokens) CreateAccessToken(_ context.Context, t *domain.AccessToken) error {
	if m.at == nil {
		m.at = map[string]*domain.AccessToken{}
	}
	cp := *t
	m.at[t.TokenHash] = &cp
	return nil
}
func (m *memTokens) GetAccessToken(_ context.Context, _ uuid.UUID, hash string) (*domain.AccessToken, error) {
	t, ok := m.at[hash]
	if !ok {
		return nil, domain.ErrAccessTokenNotFound
	}
	cp := *t
	if cp.IsExpired() {
		return &cp, domain.ErrAccessTokenExpired
	}
	return &cp, nil
}
func (m *memTokens) RevokeAccessToken(_ context.Context, _ uuid.UUID, hash string) error {
	delete(m.at, hash)
	return nil
}
func (m *memTokens) RevokeAccessTokenByJTI(_ context.Context, _ uuid.UUID, jti string) error {
	for h, t := range m.at {
		if t.JTI == jti {
			delete(m.at, h)
			return nil
		}
	}
	return nil
}
func (m *memTokens) CreateRefreshToken(_ context.Context, t *domain.RefreshToken) error {
	if m.rt == nil {
		m.rt = map[string]*domain.RefreshToken{}
	}
	cp := *t
	m.rt[t.TokenHash] = &cp
	return nil
}
func (m *memTokens) GetRefreshToken(_ context.Context, _ uuid.UUID, hash string) (*domain.RefreshToken, error) {
	t, ok := m.rt[hash]
	if !ok {
		return nil, domain.ErrRefreshTokenNotFound
	}
	cp := *t
	if cp.IsExpired() {
		return &cp, domain.ErrRefreshTokenExpired
	}
	return &cp, nil
}
func (m *memTokens) RotateRefreshToken(_ context.Context, _ uuid.UUID, oldHash string, next *domain.RefreshToken) error {
	if m.rt == nil {
		return domain.ErrRefreshTokenNotFound
	}
	if _, ok := m.rt[oldHash]; !ok {
		return domain.ErrRefreshTokenNotFound
	}
	delete(m.rt, oldHash)
	cp := *next
	m.rt[next.TokenHash] = &cp
	return nil
}
func (m *memTokens) RevokeRefreshToken(_ context.Context, _ uuid.UUID, hash string) error {
	delete(m.rt, hash)
	return nil
}
func (m *memTokens) RevokeRefreshTokensBySession(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}

func sampleLoginChallenge(t *testing.T) *domain.LoginChallenge {
	t.Helper()
	return &domain.LoginChallenge{
		TenantID:        domain.DefaultTenantID,
		ClientID:        "app-a",
		RequestURL:      "https://auth.example/oauth2/auth?client_id=app-a",
		RedirectURI:     "https://app.example/cb",
		State:           "st",
		ResponseType:    "code",
		RequestedScopes: []string{"openid"},
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}
}

func TestAcceptLoginDefaultThenAcceptConsent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)
	ch := sampleLoginChallenge(t)
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create login challenge: %v", err)
	}

	got, err := d.flow.GetLogin(ctx, ch.ID.String())
	if err != nil {
		t.Fatalf("GetLogin: %v", err)
	}
	if got.Challenge.AcceptToken == "" {
		t.Fatal("GetLogin missing accept_token")
	}

	redirect, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		Subject:     "user-1",
		Remember:    true,
	})
	if err != nil {
		t.Fatalf("AcceptLogin: %v", err)
	}
	if !strings.Contains(redirect, "login_verifier=") {
		t.Fatalf("AcceptLogin redirect = %q, want login_verifier", redirect)
	}
	if len(d.consent.byID) != 1 {
		t.Fatalf("consent challenges = %d, want 1", len(d.consent.byID))
	}
	var consent *domain.ConsentChallenge
	for _, c := range d.consent.byID {
		consent = c
	}

	redirect2, err := d.flow.AcceptConsent(ctx, oauth2.AcceptConsentInput{
		ChallengeID: consent.ID.String(),
		GrantScope:  []string{"openid"},
	})
	if err != nil {
		t.Fatalf("AcceptConsent: %v", err)
	}
	if !strings.Contains(redirect2, "consent_verifier=") {
		t.Fatalf("AcceptConsent redirect = %q", redirect2)
	}
}

func TestAcceptLoginStrictRequiresToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, true)
	ch := sampleLoginChallenge(t)
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		Subject:     "user-1",
	})
	if !errors.Is(err, oauth2.ErrAcceptTokenInvalid) {
		t.Fatalf("strict without token: err=%v", err)
	}

	_, err = d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		Subject:     "user-1",
		AcceptToken: ch.AcceptToken,
	})
	if err != nil {
		t.Fatalf("strict with token: %v", err)
	}
}

func TestAuthorizeCreatesLoginChallenge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)

	res, err := d.flow.Authorize(ctx, oauth2.AuthorizeInput{
		ClientID:            "app-a",
		ResponseType:        "code",
		RedirectURI:         "https://app.example/cb",
		Scope:               "openid",
		State:               "xyz",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		RequestURL:          "https://auth.example/oauth2/auth?client_id=app-a",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !strings.Contains(res.RedirectTo, "login_challenge=") {
		t.Fatalf("RedirectTo = %q", res.RedirectTo)
	}
	if len(d.login.byID) != 1 {
		t.Fatalf("login challenges = %d", len(d.login.byID))
	}
}

func TestAuthorizeSSOSkipsToConsent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clients := &memClients{byID: map[string]*domain.Client{
		"app-a": {
			ClientID:      "app-a",
			TenantID:      domain.DefaultTenantID,
			ClientType:    domain.ClientTypeConfidential,
			GrantTypes:    []domain.GrantType{domain.GrantTypeAuthorizationCode},
			RedirectURIs:  []string{"https://app.example/cb"},
			AllowedScopes: []string{"openid"},
			SkipConsent:   true,
		},
	}}
	lc := &memLoginChallenges{}
	cc := &memConsentChallenges{}
	sessions := &memSessions{}
	cfg := &config.Config{
		Token:   config.TokenConfig{Issuer: "https://auth.example"},
		OAuth2:  config.OAuth2Config{LoginURL: "https://consent.example/login", ConsentURL: "https://consent.example/consent"},
		Session: config.SessionConfig{DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	sess := &domain.LoginSession{
		ID:              uuid.New(),
		TenantID:        domain.DefaultTenantID,
		Subject:         "user-1",
		AuthenticatedAt: time.Now().UTC(),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	if err := sessions.Create(ctx, sess); err != nil {
		t.Fatalf("Create session: %v", err)
	}
	f := oauth2.NewFlow(cfg, clients, lc, cc, sessions, &memVerifiers{}, &memCodes{}, &memTokens{}, &memGrants{}, nil)

	res, err := f.Authorize(ctx, oauth2.AuthorizeInput{
		ClientID:          "app-a",
		ResponseType:      "code",
		RedirectURI:       "https://app.example/cb",
		Scope:             "openid",
		ExistingSessionID: sess.ID.String(),
		RequestURL:        "https://auth.example/oauth2/auth",
	})
	if err != nil {
		t.Fatalf("Authorize SSO: %v", err)
	}
	// SkipConsent=true → issue code via consent_verifier (no consent UI).
	if !strings.Contains(res.RedirectTo, "consent_verifier=") {
		t.Fatalf("SSO RedirectTo = %q, want consent_verifier", res.RedirectTo)
	}
	if len(lc.byID) != 0 {
		t.Fatal("SSO should not create login challenge")
	}
	if len(cc.byID) != 0 {
		t.Fatal("SkipConsent should not create consent challenge")
	}
}

func TestExchangeCodeAndRefresh(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)

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

	rawCode := "auth-code-raw-value"
	codeVerifier := "pkce-verifier-abcdefghijklmnopqrstuvwxyz0123456789"
	sum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if err := d.codes.Create(ctx, &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(rawCode),
		TenantID:            domain.DefaultTenantID,
		ClientID:            "app-a",
		Subject:             "user-1",
		SessionID:           sess.ID,
		RedirectURI:         "https://app.example/cb",
		Scopes:              []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Create code: %v", err)
	}

	tok, err := d.flow.ExchangeCode(ctx, oauth2.ExchangeCodeInput{
		ClientID:     "app-a",
		Code:         rawCode,
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: codeVerifier,
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken == "" || tok.TokenType != "Bearer" || tok.ExpiresIn <= 0 {
		t.Fatalf("token response incomplete: %+v", tok)
	}
	if tok.RefreshToken == "" {
		t.Fatal("expected refresh_token")
	}
	if tok.Scope != "openid offline_access" {
		t.Fatalf("scope = %q", tok.Scope)
	}

	_, err = d.flow.ExchangeCode(ctx, oauth2.ExchangeCodeInput{
		ClientID:     "app-a",
		Code:         rawCode,
		RedirectURI:  "https://app.example/cb",
		CodeVerifier: codeVerifier,
	})
	if !errors.Is(err, oauth2.ErrInvalidGrant) {
		t.Fatalf("replay: err=%v, want invalid_grant", err)
	}

	oldRT := tok.RefreshToken
	refreshed, err := d.flow.RefreshToken(ctx, oauth2.RefreshTokenInput{
		ClientID:     "app-a",
		RefreshToken: oldRT,
	})
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatalf("refresh response incomplete: %+v", refreshed)
	}
	if refreshed.RefreshToken == oldRT {
		t.Fatal("refresh token was not rotated")
	}

	_, err = d.flow.RefreshToken(ctx, oauth2.RefreshTokenInput{
		ClientID:     "app-a",
		RefreshToken: oldRT,
	})
	if !errors.Is(err, oauth2.ErrInvalidGrant) {
		t.Fatalf("old RT reuse: err=%v, want invalid_grant", err)
	}
}

func TestRevokeAndIntrospect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)

	rawAT := "opaque-access-token-value"
	at := &domain.AccessToken{
		TokenHash: domain.HashToken(rawAT),
		JTI:       uuid.NewString(),
		TenantID:  domain.DefaultTenantID,
		ClientID:  "app-a",
		Subject:   "user-1",
		Scopes:    []string{"openid"},
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := d.tokens.CreateAccessToken(ctx, at); err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	intro, err := d.flow.Introspect(ctx, oauth2.IntrospectInput{
		ClientID: "app-a",
		Token:    rawAT,
	})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !intro.Active || intro.Sub != "user-1" || intro.TokenType != "Bearer" {
		t.Fatalf("introspect = %+v", intro)
	}

	if err := d.flow.Revoke(ctx, oauth2.RevokeInput{
		ClientID: "app-a",
		Token:    rawAT,
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	intro2, err := d.flow.Introspect(ctx, oauth2.IntrospectInput{
		ClientID: "app-a",
		Token:    rawAT,
	})
	if err != nil {
		t.Fatalf("Introspect after revoke: %v", err)
	}
	if intro2.Active {
		t.Fatal("token still active after revoke")
	}

	// Unknown token: still OK.
	if err := d.flow.Revoke(ctx, oauth2.RevokeInput{
		ClientID: "app-a",
		Token:    "never-issued",
	}); err != nil {
		t.Fatalf("Revoke unknown: %v", err)
	}
}

func TestClientCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)

	secret := "super-secret-client"
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	d.clients.byID["svc"] = &domain.Client{
		ClientID:                "svc",
		TenantID:                domain.DefaultTenantID,
		ClientType:              domain.ClientTypeConfidential,
		ClientSecretHash:        string(hash),
		TokenEndpointAuthMethod: domain.TokenEndpointAuthClientSecretPost,
		GrantTypes:              []domain.GrantType{domain.GrantTypeClientCredentials},
		AllowedScopes:           []string{"api.read", "api.write"},
		DefaultScopes:           []string{"api.read"},
		Audience:                []string{"https://api.example"},
	}

	tok, err := d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "svc",
		ClientSecret: secret,
		Scope:        "api.read",
	})
	if err != nil {
		t.Fatalf("ClientCredentials: %v", err)
	}
	if tok.AccessToken == "" || tok.RefreshToken != "" || tok.IDToken != "" {
		t.Fatalf("unexpected tokens: %+v", tok)
	}
	if tok.Scope != "api.read" {
		t.Fatalf("scope = %q", tok.Scope)
	}

	intro, err := d.flow.Introspect(ctx, oauth2.IntrospectInput{
		ClientID:     "svc",
		ClientSecret: secret,
		Token:        tok.AccessToken,
	})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !intro.Active || intro.Sub != "svc" || intro.ClientID != "svc" {
		t.Fatalf("introspect = %+v", intro)
	}

	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID:     "svc",
		ClientSecret: secret,
		Scope:        "openid",
	})
	if !errors.Is(err, oauth2.ErrInvalidScope) {
		t.Fatalf("bad scope: err=%v", err)
	}

	_, err = d.flow.ClientCredentials(ctx, oauth2.ClientCredentialsInput{
		ClientID: "app-a", // public test client
	})
	if !errors.Is(err, oauth2.ErrUnauthorizedClient) {
		t.Fatalf("public client: err=%v", err)
	}
}

func TestConsentGrantRememberAndSkip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d := newTestFlow(t, false)

	ch := sampleLoginChallenge(t)
	if err := d.login.Create(ctx, ch); err != nil {
		t.Fatalf("Create login: %v", err)
	}
	redirect, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch.ID.String(),
		Subject:     "user-1",
	})
	if err != nil {
		t.Fatalf("AcceptLogin: %v", err)
	}
	if !strings.Contains(redirect, "login_verifier=") {
		t.Fatalf("first AcceptLogin = %q", redirect)
	}
	var consent *domain.ConsentChallenge
	for _, c := range d.consent.byID {
		consent = c
	}
	if consent == nil {
		t.Fatal("expected consent challenge")
	}
	if _, err := d.flow.AcceptConsent(ctx, oauth2.AcceptConsentInput{
		ChallengeID: consent.ID.String(),
		GrantScope:  []string{"openid"},
		Remember:    true,
		RememberFor: 3600,
	}); err != nil {
		t.Fatalf("AcceptConsent remember: %v", err)
	}
	if len(d.grants.byKey) != 1 {
		t.Fatalf("grants = %d, want 1", len(d.grants.byKey))
	}

	// Second login with same subject/client should skip consent UI.
	ch2 := sampleLoginChallenge(t)
	if err := d.login.Create(ctx, ch2); err != nil {
		t.Fatalf("Create login 2: %v", err)
	}
	redirect2, err := d.flow.AcceptLogin(ctx, oauth2.AcceptLoginInput{
		ChallengeID: ch2.ID.String(),
		Subject:     "user-1",
	})
	if err != nil {
		t.Fatalf("AcceptLogin 2: %v", err)
	}
	if !strings.Contains(redirect2, "consent_verifier=") {
		t.Fatalf("remembered consent redirect = %q, want consent_verifier", redirect2)
	}
	if len(d.consent.byID) != 0 {
		t.Fatal("remembered consent should not create a new consent challenge")
	}
}
