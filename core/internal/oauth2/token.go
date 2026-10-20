package oauth2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oidc"
)

// TokenResponse is the OAuth 2.0 / OIDC token endpoint success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// ExchangeCodeInput is grant_type=authorization_code.
type ExchangeCodeInput struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// RefreshTokenInput is grant_type=refresh_token.
type RefreshTokenInput struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
}

// ExchangeCode consumes an authorization code and issues opaque tokens.
func (f *Flow) ExchangeCode(ctx context.Context, in ExchangeCodeInput) (*TokenResponse, error) {
	client, err := f.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeAuthorizationCode) {
		return nil, ErrUnauthorizedClient
	}
	if strings.TrimSpace(in.Code) == "" || strings.TrimSpace(in.RedirectURI) == "" {
		return nil, fmt.Errorf("%w: code and redirect_uri are required", ErrInvalidRequest)
	}

	codeHash := domain.HashAuthorizationCode(in.Code)
	authCode, err := f.authCodes.Consume(ctx, f.tenantID(), codeHash)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrAuthorizationCodeUsed):
			return nil, ErrInvalidGrant
		case errors.Is(err, domain.ErrAuthorizationCodeNotFound),
			errors.Is(err, domain.ErrAuthorizationCodeExpired):
			return nil, ErrInvalidGrant
		default:
			return nil, err
		}
	}
	if authCode.ClientID != in.ClientID || authCode.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidGrant
	}
	if authCode.CodeChallenge != "" {
		if err := verifyCodeVerifier(in.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod); err != nil {
			return nil, err
		}
	} else if client.IsPublic() || client.RequirePKCE {
		return nil, ErrPKCERequired
	}

	return f.issueTokens(ctx, client, issueTokenOpts{
		subject:     authCode.Subject,
		sessionID:   authCode.SessionID,
		scopes:      authCode.Scopes,
		audience:    authCode.Audience,
		extra:       authCode.ExtraClaims,
		nonce:       authCode.Nonce,
		skipRefresh: false,
	})
}

// RefreshToken rotates the refresh token and issues a new access token.
func (f *Flow) RefreshToken(ctx context.Context, in RefreshTokenInput) (*TokenResponse, error) {
	client, err := f.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, err
	}
	if !client.HasGrantType(domain.GrantTypeRefreshToken) {
		return nil, ErrUnauthorizedClient
	}
	if strings.TrimSpace(in.RefreshToken) == "" {
		return nil, fmt.Errorf("%w: refresh_token is required", ErrInvalidRequest)
	}

	oldHash := domain.HashToken(in.RefreshToken)
	old, err := f.tokens.GetRefreshToken(ctx, f.tenantID(), oldHash)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if old.ClientID != in.ClientID {
		return nil, ErrInvalidGrant
	}
	if old.SessionID != uuid.Nil {
		sess, err := f.loginSessions.GetByID(ctx, old.SessionID)
		if err != nil || sess.IsExpired() {
			_ = f.tokens.RevokeRefreshToken(ctx, f.tenantID(), oldHash)
			return nil, ErrSessionExpired
		}
	}

	scopes := old.Scopes
	if in.Scope != "" {
		scopes = intersectScopes(scopes, parseSpaceList(in.Scope))
	}

	rawRT, err := newRawSecret()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	next := &domain.RefreshToken{
		TokenHash: domain.HashToken(rawRT),
		JTI:       uuid.NewString(),
		TenantID:  f.tenantID(),
		ClientID:  old.ClientID,
		Subject:   old.Subject,
		SessionID: old.SessionID,
		Scopes:    scopes,
		Audience:  old.Audience,
		Extra:     old.Extra,
		IssuedAt:  now,
		ExpiresAt: now.Add(f.refreshTTL(client)),
	}
	if err := f.tokens.RotateRefreshToken(ctx, f.tenantID(), oldHash, next); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	resp, err := f.issueTokens(ctx, client, issueTokenOpts{
		subject:     old.Subject,
		sessionID:   old.SessionID,
		scopes:      scopes,
		audience:    old.Audience,
		extra:       old.Extra,
		skipRefresh: true,
	})
	if err != nil {
		return nil, err
	}
	resp.RefreshToken = rawRT
	return resp, nil
}

type issueTokenOpts struct {
	subject     string
	sessionID   uuid.UUID
	scopes      []string
	audience    []string
	extra       map[string]any
	nonce       string
	skipRefresh bool
}

func (f *Flow) issueTokens(ctx context.Context, client *domain.Client, opts issueTokenOpts) (*TokenResponse, error) {
	now := time.Now().UTC()
	atTTL := f.accessTTL(client)
	rawAT, err := newRawSecret()
	if err != nil {
		return nil, err
	}
	at := &domain.AccessToken{
		TokenHash: domain.HashToken(rawAT),
		JTI:       uuid.NewString(),
		TenantID:  f.tenantID(),
		ClientID:  client.ClientID,
		Subject:   opts.subject,
		SessionID: opts.sessionID,
		Scopes:    opts.scopes,
		Audience:  opts.audience,
		Extra:     opts.extra,
		IssuedAt:  now,
		ExpiresAt: now.Add(atTTL),
	}
	if err := f.tokens.CreateAccessToken(ctx, at); err != nil {
		return nil, fmt.Errorf("store access token: %w", err)
	}

	resp := &TokenResponse{
		AccessToken: rawAT,
		TokenType:   "Bearer",
		ExpiresIn:   int(atTTL.Seconds()),
		Scope:       strings.Join(opts.scopes, " "),
	}

	if idToken, err := f.issueIDToken(ctx, client, opts); err != nil {
		return nil, err
	} else if idToken != "" {
		resp.IDToken = idToken
	}

	if opts.skipRefresh {
		return resp, nil
	}
	// RT when client allows refresh_token and we have a login session (opaque session binding).
	if opts.sessionID == uuid.Nil || !client.HasGrantType(domain.GrantTypeRefreshToken) {
		return resp, nil
	}

	rawRT, err := newRawSecret()
	if err != nil {
		return nil, err
	}
	rt := &domain.RefreshToken{
		TokenHash: domain.HashToken(rawRT),
		JTI:       uuid.NewString(),
		TenantID:  f.tenantID(),
		ClientID:  client.ClientID,
		Subject:   opts.subject,
		SessionID: opts.sessionID,
		Scopes:    opts.scopes,
		Audience:  opts.audience,
		Extra:     opts.extra,
		IssuedAt:  now,
		ExpiresAt: now.Add(f.refreshTTL(client)),
	}
	if err := f.tokens.CreateRefreshToken(ctx, rt); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}
	resp.RefreshToken = rawRT
	return resp, nil
}

func (f *Flow) issueIDToken(ctx context.Context, client *domain.Client, opts issueTokenOpts) (string, error) {
	if f.idTokens == nil {
		return "", nil
	}
	var authTime time.Time
	if opts.sessionID != uuid.Nil {
		if sess, err := f.loginSessions.GetByID(ctx, opts.sessionID); err == nil {
			authTime = sess.AuthenticatedAt
		}
	}
	return f.idTokens.Issue(ctx, oidc.IssueInput{
		ClientID:   client.ClientID,
		Subject:    opts.subject,
		SessionID:  opts.sessionID,
		AuthTime:   authTime,
		Nonce:      opts.nonce,
		Scopes:     opts.scopes,
		Extra:      opts.extra,
		IDTokenTTL: client.IDTokenTTL,
	})
}

func (f *Flow) accessTTL(client *domain.Client) time.Duration {
	if client.AccessTokenTTL != nil && *client.AccessTokenTTL > 0 {
		return *client.AccessTokenTTL
	}
	if f.cfg.Token.AccessTokenTTL > 0 {
		return f.cfg.Token.AccessTokenTTL
	}
	return time.Hour
}

func (f *Flow) refreshTTL(client *domain.Client) time.Duration {
	if client.RefreshTokenTTL != nil && *client.RefreshTokenTTL > 0 {
		return *client.RefreshTokenTTL
	}
	if f.cfg.Token.RefreshTokenTTL > 0 {
		return f.cfg.Token.RefreshTokenTTL
	}
	return 720 * time.Hour
}

func intersectScopes(have, want []string) []string {
	if len(want) == 0 {
		return have
	}
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	var out []string
	for _, s := range want {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
