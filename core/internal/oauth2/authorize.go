package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
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
	// Prompt is the raw OIDC prompt query (space-separated).
	Prompt string
	// MaxAge is the raw OIDC max_age query (seconds); empty = omitted.
	MaxAge string
	// ExistingSessionID from SSO cookie (may be empty / invalid).
	ExistingSessionID string
	// DeviceID from browser device cookie (granto_did); stored on LoginChallenge.
	DeviceID string
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
		f.auditAuthorizeFailure(ctx, strings.TrimSpace(in.ClientID), ErrInvalidRequest)
		return nil, fmt.Errorf("%w: client_id and redirect_uri are required", ErrInvalidRequest)
	}

	client, err := f.clients.GetByClientID(ctx, f.tenantID(), in.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			f.auditAuthorizeFailure(ctx, in.ClientID, ErrInvalidClient)
			return nil, ErrInvalidClient
		}
		return nil, err
	}
	// Validate redirect_uri before any client-redirectable error (RFC 6749 §4.1.2.1).
	if !client.HasRedirectURI(in.RedirectURI) {
		f.auditAuthorizeFailure(ctx, in.ClientID, ErrInvalidRedirectURI)
		return nil, ErrInvalidRedirectURI
	}
	toClient := func(err error) error {
		f.auditAuthorizeFailure(ctx, in.ClientID, err)
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

	prompt, err := parsePrompt(in.Prompt)
	if err != nil {
		return nil, toClient(err)
	}
	maxAge, maxAgeSet, err := parseMaxAge(in.MaxAge)
	if err != nil {
		return nil, toClient(err)
	}

	var maxAgePtr *int64
	if maxAgeSet {
		v := maxAge
		maxAgePtr = &v
	}
	oidcCtx := domain.OIDCContext{
		LoginHint:     in.LoginHint,
		Display:       in.Display,
		ACRValues:     parseSpaceList(in.ACRValues),
		UILocales:     parseSpaceList(in.UILocales),
		Prompt:        prompt,
		MaxAgeSeconds: maxAgePtr,
	}

	now := time.Now().UTC()
	var sessionID uuid.UUID
	var subject string
	var sess *domain.LoginSession
	skipLogin := false

	if sid, err := uuid.Parse(strings.TrimSpace(in.ExistingSessionID)); err == nil && sid != uuid.Nil {
		if s, err := f.loginSessions.GetByID(ctx, sid); err == nil && !s.IsExpired() && s.TenantID == f.tenantID() {
			sess = s
		}
	}

	forceLogin := slices.Contains(prompt, "login") || slices.Contains(prompt, "select_account")
	if sess != nil && maxAgeSet && sessionExceedsMaxAge(sess, maxAge, now) {
		if slices.Contains(prompt, "none") {
			return nil, toClient(fmt.Errorf("%w: authentication time exceeds max_age", ErrLoginRequired))
		}
		forceLogin = true
	}

	if sess != nil && !forceLogin {
		sessionID = sess.ID
		subject = sess.Subject
		skipLogin = true
	}

	if skipLogin {
		forceConsent := slices.Contains(prompt, "consent")
		canSkip := !forceConsent && f.canSkipConsentUI(ctx, client, subject, scopes, nil)
		if !canSkip && slices.Contains(prompt, "none") {
			return nil, toClient(fmt.Errorf("%w: consent is required", ErrConsentRequired))
		}
		if canSkip {
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
		f.auditSuccess(ctx, domain.AuditEventConsentChallengeCreated, domain.AuditActorSystem, subject, func(e *domain.AuditEvent) {
			e.SubjectType = domain.AuditSubjectUser
			e.SubjectID = subject
			e.ClientID = client.ClientID
			e.SessionID = sessionID.String()
			e.Metadata = map[string]any{"challenge_id": consent.ID.String(), "source": "authorize"}
		})
		redirect, err := buildConsentUIURL(f.consentURL(), consent.ID.String())
		if err != nil {
			return nil, err
		}
		return &AuthorizeResult{RedirectTo: redirect}, nil
	}

	if slices.Contains(prompt, "none") {
		return nil, toClient(fmt.Errorf("%w: no existing login session", ErrLoginRequired))
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
		SessionID:           uuid.Nil, // force re-auth; do not skip via old session
		Skip:                false,
		DeviceID:            strings.TrimSpace(in.DeviceID),
		OIDCContext:         oidcCtx,
		ExpiresAt:           now.Add(defaultChallengeTTL),
		CreatedAt:           now,
	}
	if err := f.loginChallenges.Create(ctx, ch); err != nil {
		return nil, fmt.Errorf("create login challenge: %w", err)
	}
	f.auditSuccess(ctx, domain.AuditEventLoginChallengeCreated, domain.AuditActorSystem, "", func(e *domain.AuditEvent) {
		e.ClientID = client.ClientID
		e.Metadata = map[string]any{"challenge_id": ch.ID.String()}
	})

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

func parsePrompt(raw string) ([]string, error) {
	parts := parseSpaceList(raw)
	if len(parts) == 0 {
		return nil, nil
	}
	hasNone := false
	for _, p := range parts {
		switch p {
		case "none":
			hasNone = true
		case "login", "consent", "select_account":
			// ok
		default:
			return nil, fmt.Errorf("%w: unsupported prompt value %q", ErrInvalidRequest, p)
		}
	}
	if hasNone && len(parts) > 1 {
		return nil, fmt.Errorf("%w: prompt none cannot be combined with other values", ErrInvalidRequest)
	}
	return parts, nil
}

func parseMaxAge(raw string) (seconds int64, set bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, false, fmt.Errorf("%w: max_age must be a non-negative integer", ErrInvalidRequest)
	}
	return v, true, nil
}

func sessionExceedsMaxAge(sess *domain.LoginSession, maxAge int64, now time.Time) bool {
	if sess == nil {
		return true
	}
	deadline := sess.AuthenticatedAt.UTC().Add(time.Duration(maxAge) * time.Second)
	return !deadline.After(now.UTC())
}
