package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// LoginRequest is returned by GetLogin.
type LoginRequest struct {
	Challenge *domain.LoginChallenge
	Subject   string // from existing session when skip
}

// AcceptLoginInput is the Admin AcceptLogin payload.
type AcceptLoginInput struct {
	ChallengeID               string
	Subject                   string
	Remember                  bool
	RememberFor               int64
	ACR                       string
	AMR                       []string
	Context                   map[string]any
	IdentityProviderSessionID string
	AcceptToken               string
}

// RejectInput is shared by login/consent reject.
type RejectInput struct {
	ChallengeID      string
	Error            string
	ErrorDescription string
	ErrorHint        string
	AcceptToken      string
}

// GetLogin loads a login challenge (includes accept_token).
func (f *Flow) GetLogin(ctx context.Context, challengeID string) (*LoginRequest, error) {
	id, err := parseChallengeID(challengeID)
	if err != nil {
		return nil, err
	}
	ch, err := f.loginChallenges.Get(ctx, f.tenantID(), id)
	if err != nil {
		return nil, mapChallengeErr(err)
	}
	out := &LoginRequest{Challenge: ch}
	if ch.SessionID != uuid.Nil {
		if sess, err := f.loginSessions.GetByID(ctx, ch.SessionID); err == nil && !sess.IsExpired() {
			out.Subject = sess.Subject
		}
	}
	return out, nil
}

// AcceptLogin consumes the login challenge, creates a login session + consent challenge,
// and returns a redirect to the AS with login_verifier.
func (f *Flow) AcceptLogin(ctx context.Context, in AcceptLoginInput) (redirectTo string, err error) {
	if strings.TrimSpace(in.Subject) == "" {
		return "", fmt.Errorf("%w: subject is required", ErrInvalidRequest)
	}
	id, err := parseChallengeID(in.ChallengeID)
	if err != nil {
		return "", err
	}

	ch, err := f.loginChallenges.Consume(ctx, f.tenantID(), id, consumeOpts(in.AcceptToken, f.cfg.Admin.AcceptStrict))
	if err != nil {
		return "", mapChallengeErr(err)
	}

	now := time.Now().UTC()
	session := &domain.LoginSession{
		ID:                        uuid.New(),
		TenantID:                  ch.TenantID,
		Subject:                   in.Subject,
		AuthenticatedAt:           now,
		ExpiresAt:                 sessionExpiry(in.Remember, in.RememberFor, f.cfg.Session.DefaultTTL, f.cfg.Session.MaxTTL),
		Remember:                  in.Remember,
		DeviceID:                  ch.DeviceID,
		ACR:                       in.ACR,
		AMR:                       in.AMR,
		IdentityProviderSessionID: in.IdentityProviderSessionID,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if session.AMR == nil {
		session.AMR = []string{}
	}
	if err := f.loginSessions.Create(ctx, session); err != nil {
		return "", fmt.Errorf("create login session: %w", err)
	}
	f.auditSuccess(ctx, domain.AuditEventLoginAccepted, domain.AuditActorAdmin, in.Subject, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectUser
		e.SubjectID = in.Subject
		e.ClientID = ch.ClientID
		e.SessionID = session.ID.String()
		e.Metadata = map[string]any{"challenge_id": ch.ID.String()}
	})
	f.auditSuccess(ctx, domain.AuditEventSessionCreated, domain.AuditActorAdmin, in.Subject, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectSession
		e.SubjectID = session.ID.String()
		e.ClientID = ch.ClientID
		e.SessionID = session.ID.String()
	})

	client, err := f.clients.GetByClientID(ctx, f.tenantID(), ch.ClientID)
	if err != nil {
		return "", err
	}
	if f.canSkipConsentUI(ctx, client, in.Subject, ch.RequestedScopes, ch.RequestedAudience) {
		extra := map[string]any{}
		if in.Context != nil {
			extra["context"] = in.Context
		}
		return f.issueConsentCodeAndVerifier(ctx, consentIssueParams{
			TenantID:            ch.TenantID,
			ClientID:            ch.ClientID,
			Subject:             in.Subject,
			SessionID:           session.ID,
			RedirectURI:         ch.RedirectURI,
			State:               ch.State,
			Scopes:              ch.RequestedScopes,
			Audience:            ch.RequestedAudience,
			Nonce:               ch.Nonce,
			CodeChallenge:       ch.CodeChallenge,
			CodeChallengeMethod: ch.CodeChallengeMethod,
			Extra:               extra,
		})
	}

	consent := &domain.ConsentChallenge{
		TenantID:            ch.TenantID,
		LoginChallengeID:    ch.ID,
		SessionID:           session.ID,
		Subject:             in.Subject,
		ClientID:            ch.ClientID,
		RequestURL:          ch.RequestURL,
		RedirectURI:         ch.RedirectURI,
		State:               ch.State,
		ResponseType:        ch.ResponseType,
		RequestedScopes:     ch.RequestedScopes,
		RequestedAudience:   ch.RequestedAudience,
		Nonce:               ch.Nonce,
		CodeChallenge:       ch.CodeChallenge,
		CodeChallengeMethod: ch.CodeChallengeMethod,
		Skip:                false,
		ACR:                 in.ACR,
		AMR:                 in.AMR,
		Context:             in.Context,
		OIDCContext:         ch.OIDCContext,
		ExpiresAt:           now.Add(defaultChallengeTTL),
		CreatedAt:           now,
	}
	if consent.AMR == nil {
		consent.AMR = []string{}
	}
	if err := f.consentChallenges.Create(ctx, consent); err != nil {
		return "", fmt.Errorf("create consent challenge: %w", err)
	}
	f.auditSuccess(ctx, domain.AuditEventConsentChallengeCreated, domain.AuditActorSystem, in.Subject, func(e *domain.AuditEvent) {
		e.SubjectType = domain.AuditSubjectUser
		e.SubjectID = in.Subject
		e.ClientID = ch.ClientID
		e.SessionID = session.ID.String()
		e.Metadata = map[string]any{"challenge_id": consent.ID.String()}
	})

	consentUI, err := buildConsentUIURL(f.consentURL(), consent.ID.String())
	if err != nil {
		return "", err
	}

	verifier := &domain.FlowVerifier{
		TenantID:   ch.TenantID,
		Kind:       domain.FlowVerifierKindLogin,
		SessionID:  session.ID,
		RedirectTo: consentUI,
		ExpiresAt:  now.Add(defaultVerifierTTL),
		CreatedAt:  now,
	}
	if err := f.flowVerifiers.Create(ctx, verifier); err != nil {
		return "", fmt.Errorf("create flow verifier: %w", err)
	}

	return buildASVerifierURL(f.issuer(), domain.FlowVerifierKindLogin, verifier.ID), nil
}

// RejectLogin deletes the login challenge and returns a client error redirect via AS verifier
// when redirect_uri is present; otherwise returns empty redirect (caller may show error page).
func (f *Flow) RejectLogin(ctx context.Context, in RejectInput) (redirectTo string, err error) {
	id, err := parseChallengeID(in.ChallengeID)
	if err != nil {
		return "", err
	}

	// Load first so we can build error redirect; then delete (reject does not require accept_token match in default,
	// but if a wrong token is sent with RequireToken we still validate via Consume when strict).
	ch, err := f.loginChallenges.Get(ctx, f.tenantID(), id)
	if err != nil {
		return "", mapChallengeErr(err)
	}
	if f.cfg.Admin.AcceptStrict || in.AcceptToken != "" {
		if !ch.ValidAcceptToken(in.AcceptToken) {
			return "", ErrAcceptTokenInvalid
		}
	}
	if err := f.loginChallenges.Delete(ctx, f.tenantID(), id); err != nil {
		return "", mapChallengeErr(err)
	}
	f.auditFailure(ctx, domain.AuditEventLoginRejected, domain.AuditActorAdmin, "", in.Error, func(e *domain.AuditEvent) {
		e.ClientID = ch.ClientID
		e.Metadata = map[string]any{
			"challenge_id":      ch.ID.String(),
			"error_description": in.ErrorDescription,
		}
	})

	clientURL, err := buildClientErrorURL(ch.RedirectURI, ch.State, in.Error, in.ErrorDescription, in.ErrorHint)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	sessionID := ch.SessionID
	verifier := &domain.FlowVerifier{
		TenantID:   ch.TenantID,
		Kind:       domain.FlowVerifierKindLogin,
		SessionID:  sessionID,
		RedirectTo: clientURL,
		ExpiresAt:  now.Add(defaultVerifierTTL),
		CreatedAt:  now,
	}
	// SessionID may be Nil on reject before login — FlowVerifier Create requires non-nil.
	// Use a nil-session sentinel: skip verifier and return client URL directly when no session.
	if sessionID == uuid.Nil {
		return clientURL, nil
	}
	if err := f.flowVerifiers.Create(ctx, verifier); err != nil {
		return "", fmt.Errorf("create flow verifier: %w", err)
	}
	return buildASVerifierURL(f.issuer(), domain.FlowVerifierKindLogin, verifier.ID), nil
}
