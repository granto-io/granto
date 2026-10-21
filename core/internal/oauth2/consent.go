package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

// ConsentRequest is returned by GetConsent.
type ConsentRequest struct {
	Challenge *domain.ConsentChallenge
}

// AcceptConsentInput is the Admin AcceptConsent payload.
type AcceptConsentInput struct {
	ChallengeID    string
	GrantScope     []string
	GrantAudience  []string
	Remember       bool
	RememberFor    int64
	SessionAccess  map[string]any
	SessionIDToken map[string]any
	Context        map[string]any
	AcceptToken    string
}

// GetConsent loads a consent challenge (includes accept_token).
func (f *Flow) GetConsent(ctx context.Context, challengeID string) (*ConsentRequest, error) {
	id, err := parseChallengeID(challengeID)
	if err != nil {
		return nil, err
	}
	ch, err := f.consentChallenges.Get(ctx, f.tenantID(), id)
	if err != nil {
		return nil, mapChallengeErr(err)
	}
	return &ConsentRequest{Challenge: ch}, nil
}

// AcceptConsent consumes the consent challenge, stores an authorization code,
// and returns a redirect to the AS with consent_verifier.
func (f *Flow) AcceptConsent(ctx context.Context, in AcceptConsentInput) (redirectTo string, err error) {
	id, err := parseChallengeID(in.ChallengeID)
	if err != nil {
		return "", err
	}

	ch, err := f.consentChallenges.Consume(ctx, f.tenantID(), id, consumeOpts(in.AcceptToken, f.cfg.Admin.AcceptStrict))
	if err != nil {
		return "", mapChallengeErr(err)
	}

	scopes := in.GrantScope
	if len(scopes) == 0 {
		scopes = ch.RequestedScopes
	}
	audience := in.GrantAudience
	if len(audience) == 0 {
		audience = ch.RequestedAudience
	}

	extra := map[string]any{}
	if in.SessionAccess != nil {
		extra["access_token"] = in.SessionAccess
	}
	if in.SessionIDToken != nil {
		extra["id_token"] = in.SessionIDToken
	}
	if in.Context != nil {
		extra["context"] = in.Context
	} else if ch.Context != nil {
		extra["context"] = ch.Context
	}

	redirect, err := f.issueConsentCodeAndVerifier(ctx, consentIssueParams{
		TenantID:            ch.TenantID,
		ClientID:            ch.ClientID,
		Subject:             ch.Subject,
		SessionID:           ch.SessionID,
		RedirectURI:         ch.RedirectURI,
		State:               ch.State,
		Scopes:              scopes,
		Audience:            audience,
		Nonce:               ch.Nonce,
		CodeChallenge:       ch.CodeChallenge,
		CodeChallengeMethod: ch.CodeChallengeMethod,
		ConsentChallengeID:  ch.ID,
		Extra:               extra,
	})
	if err != nil {
		return "", err
	}

	if err := f.rememberConsentGrant(ctx, ch.Subject, ch.ClientID, scopes, audience, in.Remember, in.RememberFor); err != nil {
		return "", err
	}

	return redirect, nil
}

// RejectConsent deletes the consent challenge and returns an error redirect (via verifier when possible).
func (f *Flow) RejectConsent(ctx context.Context, in RejectInput) (redirectTo string, err error) {
	id, err := parseChallengeID(in.ChallengeID)
	if err != nil {
		return "", err
	}

	ch, err := f.consentChallenges.Get(ctx, f.tenantID(), id)
	if err != nil {
		return "", mapChallengeErr(err)
	}
	if f.cfg.Admin.AcceptStrict || in.AcceptToken != "" {
		if !ch.ValidAcceptToken(in.AcceptToken) {
			return "", ErrAcceptTokenInvalid
		}
	}
	if err := f.consentChallenges.Delete(ctx, f.tenantID(), id); err != nil {
		return "", mapChallengeErr(err)
	}

	clientURL, err := buildClientErrorURL(ch.RedirectURI, ch.State, in.Error, in.ErrorDescription, in.ErrorHint)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	if ch.SessionID == uuid.Nil {
		return clientURL, nil
	}
	verifier := &domain.FlowVerifier{
		TenantID:   ch.TenantID,
		Kind:       domain.FlowVerifierKindConsent,
		SessionID:  ch.SessionID,
		RedirectTo: clientURL,
		ExpiresAt:  now.Add(defaultVerifierTTL),
		CreatedAt:  now,
	}
	if err := f.flowVerifiers.Create(ctx, verifier); err != nil {
		return "", fmt.Errorf("create flow verifier: %w", err)
	}
	return buildASVerifierURL(f.issuer(), domain.FlowVerifierKindConsent, verifier.ID), nil
}
