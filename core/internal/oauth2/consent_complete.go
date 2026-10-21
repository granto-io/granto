package oauth2

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/domain"
)

type consentIssueParams struct {
	TenantID            uuid.UUID
	ClientID            string
	Subject             string
	SessionID           uuid.UUID
	RedirectURI         string
	State               string
	Scopes              []string
	Audience            []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ConsentChallengeID  uuid.UUID
	Extra               map[string]any
}

// issueConsentCodeAndVerifier stores an authorization code and returns AS redirect with consent_verifier.
func (f *Flow) issueConsentCodeAndVerifier(ctx context.Context, p consentIssueParams) (string, error) {
	if p.SessionID == uuid.Nil {
		return "", fmt.Errorf("%w: consent missing session", ErrInvalidRequest)
	}
	rawCode, err := newRawSecret()
	if err != nil {
		return "", fmt.Errorf("generate authorization code: %w", err)
	}
	now := time.Now().UTC()
	code := &domain.AuthorizationCode{
		CodeHash:            domain.HashAuthorizationCode(rawCode),
		TenantID:            p.TenantID,
		ClientID:            p.ClientID,
		Subject:             p.Subject,
		SessionID:           p.SessionID,
		RedirectURI:         p.RedirectURI,
		Scopes:              p.Scopes,
		Audience:            p.Audience,
		Nonce:               p.Nonce,
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
		ConsentChallengeID:  p.ConsentChallengeID,
		ExtraClaims:         p.Extra,
		ExpiresAt:           now.Add(defaultAuthCodeTTL),
		CreatedAt:           now,
	}
	if err := f.authCodes.Create(ctx, code); err != nil {
		return "", fmt.Errorf("store authorization code: %w", err)
	}

	clientURL, err := buildClientCallbackURL(p.RedirectURI, rawCode, p.State)
	if err != nil {
		return "", err
	}
	verifier := &domain.FlowVerifier{
		TenantID:   p.TenantID,
		Kind:       domain.FlowVerifierKindConsent,
		SessionID:  p.SessionID,
		RedirectTo: clientURL,
		ExpiresAt:  now.Add(defaultVerifierTTL),
		CreatedAt:  now,
	}
	if err := f.flowVerifiers.Create(ctx, verifier); err != nil {
		return "", fmt.Errorf("create flow verifier: %w", err)
	}
	return buildASVerifierURL(f.issuer(), domain.FlowVerifierKindConsent, verifier.ID), nil
}

// canSkipConsentUI reports whether consent UI can be skipped (client.SkipConsent or grant).
func (f *Flow) canSkipConsentUI(
	ctx context.Context,
	client *domain.Client,
	subject string,
	scopes, audience []string,
) bool {
	if client.SkipConsent {
		return true
	}
	if f.consentGrants == nil || subject == "" {
		return false
	}
	grant, err := f.consentGrants.Get(ctx, f.tenantID(), subject, client.ClientID)
	if err != nil {
		return false
	}
	return grant.CoversScopes(scopes) && grant.CoversAudience(audience)
}

func (f *Flow) rememberConsentGrant(
	ctx context.Context,
	subject, clientID string,
	scopes, audience []string,
	remember bool,
	rememberFor int64,
) error {
	if !remember || f.consentGrants == nil || subject == "" {
		return nil
	}
	var expiresAt *time.Time
	if rememberFor > 0 {
		t := time.Now().UTC().Add(time.Duration(rememberFor) * time.Second)
		expiresAt = &t
	}
	grant := &domain.ConsentGrant{
		TenantID:  f.tenantID(),
		Subject:   subject,
		ClientID:  clientID,
		Scopes:    append([]string(nil), scopes...),
		Audience:  append([]string(nil), audience...),
		ExpiresAt: expiresAt,
	}
	if err := f.consentGrants.Upsert(ctx, grant); err != nil {
		return fmt.Errorf("store consent grant: %w", err)
	}
	return nil
}
