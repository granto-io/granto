package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// AuthorizeInput is a public /oauth2/auth authorize request (no verifier).
type AuthorizeInput struct {
	ClientID            string
	ResponseType        string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	// OIDC
	LoginHint string
	ACRValues string
	UILocales string
	Display   string
	// ExistingSessionID from SSO cookie (may be empty / invalid).
	ExistingSessionID string
	// RequestURL is the full authorize URL for challenge.RequestURL.
	RequestURL string
}

// AuthorizeResult is either a redirect to login/consent UI.
type AuthorizeResult struct {
	RedirectTo string
}

// Authorize validates the request, creates a LoginChallenge (or ConsentChallenge
// when SSO session is already valid), and returns a browser redirect.
func (f *Flow) Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeResult, error) {
	if strings.TrimSpace(in.ClientID) == "" || strings.TrimSpace(in.RedirectURI) == "" {
		return nil, fmt.Errorf("%w: client_id and redirect_uri are required", ErrInvalidRequest)
	}

	client, err := f.clients.GetByClientID(ctx, f.tenantID(), in.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	// Validate redirect_uri before any client-redirectable error (RFC 6749 §4.1.2.1).
	if !client.HasRedirectURI(in.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	toClient := func(err error) error {
		return clientRedirect(err, in.RedirectURI, in.State)
	}

	if in.ResponseType != "code" {
		return nil, toClient(ErrUnsupportedResponseType)
	}
	if !client.HasGrantType(domain.GrantTypeAuthorizationCode) {
		return nil, toClient(ErrUnauthorizedClient)
	}

	scopes := parseSpaceList(in.Scope)
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.DefaultScopes...)
	}
	for _, scope := range scopes {
		if !client.HasScope(scope) {
			return nil, toClient(fmt.Errorf("%w: %s", ErrInvalidScope, scope))
		}
	}

	if client.IsPublic() || client.RequirePKCE {
		if in.CodeChallenge == "" {
			return nil, toClient(ErrPKCERequired)
		}
	}
	if in.CodeChallenge != "" {
		if err := validateCodeChallengeMethod(in.CodeChallengeMethod); err != nil {
			return nil, toClient(err)
		}
	}

	oidcCtx := domain.OIDCContext{
		LoginHint: in.LoginHint,
		Display:   in.Display,
		ACRValues: parseSpaceList(in.ACRValues),
		UILocales: parseSpaceList(in.UILocales),
	}

	now := time.Now().UTC()
	var sessionID uuid.UUID
	var subject string
	skipLogin := false

	if sid, err := uuid.Parse(strings.TrimSpace(in.ExistingSessionID)); err == nil && sid != uuid.Nil {
		if sess, err := f.loginSessions.GetByID(ctx, sid); err == nil && !sess.IsExpired() && sess.TenantID == f.tenantID() {
			sessionID = sess.ID
			subject = sess.Subject
			skipLogin = true
		}
	}

	if skipLogin {
		if f.canSkipConsentUI(ctx, client, subject, scopes, nil) {
			redirect, err := f.issueConsentCodeAndVerifier(ctx, consentIssueParams{
				TenantID:            f.tenantID(),
				ClientID:            client.ClientID,
				Subject:             subject,
				SessionID:           sessionID,
				RedirectURI:         in.RedirectURI,
				State:               in.State,
				Scopes:              scopes,
				Nonce:               in.Nonce,
				CodeChallenge:       in.CodeChallenge,
				CodeChallengeMethod: in.CodeChallengeMethod,
			})
			if err != nil {
				return nil, err
			}
			return &AuthorizeResult{RedirectTo: redirect}, nil
		}
		consent := &domain.ConsentChallenge{
			TenantID:            f.tenantID(),
			SessionID:           sessionID,
			Subject:             subject,
			ClientID:            client.ClientID,
			RequestURL:          in.RequestURL,
			RedirectURI:         in.RedirectURI,
			State:               in.State,
			ResponseType:        in.ResponseType,
			RequestedScopes:     scopes,
			Nonce:               in.Nonce,
			CodeChallenge:       in.CodeChallenge,
			CodeChallengeMethod: in.CodeChallengeMethod,
			Skip:                false,
			OIDCContext:         oidcCtx,
			ExpiresAt:           now.Add(defaultChallengeTTL),
			CreatedAt:           now,
		}
		if err := f.consentChallenges.Create(ctx, consent); err != nil {
			return nil, fmt.Errorf("create consent challenge: %w", err)
		}
		redirect, err := buildConsentUIURL(f.consentURL(), consent.ID.String())
		if err != nil {
			return nil, err
		}
		return &AuthorizeResult{RedirectTo: redirect}, nil
	}

	ch := &domain.LoginChallenge{
		TenantID:            f.tenantID(),
		ClientID:            client.ClientID,
		RequestURL:          in.RequestURL,
		RedirectURI:         in.RedirectURI,
		State:               in.State,
		ResponseType:        in.ResponseType,
		RequestedScopes:     scopes,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		SessionID:           sessionID,
		Skip:                false,
		OIDCContext:         oidcCtx,
		ExpiresAt:           now.Add(defaultChallengeTTL),
		CreatedAt:           now,
	}
	if err := f.loginChallenges.Create(ctx, ch); err != nil {
		return nil, fmt.Errorf("create login challenge: %w", err)
	}

	redirect, err := buildLoginUIURL(f.cfg.OAuth2.LoginURL, ch.ID.String())
	if err != nil {
		return nil, err
	}
	return &AuthorizeResult{RedirectTo: redirect}, nil
}

func buildLoginUIURL(base, challengeID string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse login url: %w", err)
	}
	q := u.Query()
	q.Set("login_challenge", challengeID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func parseSpaceList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func validateCodeChallengeMethod(method string) error {
	switch method {
	case "", "S256", "plain":
		return nil
	default:
		return fmt.Errorf("%w: unsupported code_challenge_method", ErrInvalidRequest)
	}
}
