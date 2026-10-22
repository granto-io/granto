package oauth2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/domain"
	"github.com/granto-io/granto/core/internal/oidc"
	"github.com/granto-io/granto/core/internal/repository"
)

const (
	defaultChallengeTTL = 30 * time.Minute
	defaultVerifierTTL  = 5 * time.Minute
	defaultAuthCodeTTL  = 10 * time.Minute
)

// Flow handles Admin login/consent and public /oauth2/auth orchestration.
type Flow struct {
	cfg               *config.Config
	clients           repository.ClientRepository
	loginChallenges   repository.LoginChallengeRepository
	consentChallenges repository.ConsentChallengeRepository
	loginSessions     repository.LoginSessionRepository
	flowVerifiers     repository.FlowVerifierRepository
	authCodes         repository.AuthorizationCodeRepository
	tokens            repository.TokenRepository
	consentGrants     repository.ConsentGrantRepository
	idTokens          *oidc.IDTokens
	httpClient        *http.Client // back-channel logout override (tests); nil → SSRF-safe client
}

// NewFlow constructs an OAuth2 flow orchestrator.
func NewFlow(
	cfg *config.Config,
	clients repository.ClientRepository,
	loginChallenges repository.LoginChallengeRepository,
	consentChallenges repository.ConsentChallengeRepository,
	loginSessions repository.LoginSessionRepository,
	flowVerifiers repository.FlowVerifierRepository,
	authCodes repository.AuthorizationCodeRepository,
	tokens repository.TokenRepository,
	consentGrants repository.ConsentGrantRepository,
	idTokens *oidc.IDTokens,
) *Flow {
	return &Flow{
		cfg:               cfg,
		clients:           clients,
		loginChallenges:   loginChallenges,
		consentChallenges: consentChallenges,
		loginSessions:     loginSessions,
		flowVerifiers:     flowVerifiers,
		authCodes:         authCodes,
		tokens:            tokens,
		consentGrants:     consentGrants,
		idTokens:          idTokens,
	}
}

func (f *Flow) tenantID() uuid.UUID {
	return domain.DefaultTenantID
}

func (f *Flow) issuer() string {
	return strings.TrimRight(f.cfg.Token.Issuer, "/")
}

func (f *Flow) consentURL() string {
	if f.cfg.OAuth2.ConsentURL != "" {
		return f.cfg.OAuth2.ConsentURL
	}
	return f.cfg.OAuth2.LoginURL
}

func parseChallengeID(raw string) (uuid.UUID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil || id == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: invalid challenge id", ErrInvalidRequest)
	}
	return id, nil
}

func consumeOpts(acceptToken string, strict bool) repository.ChallengeConsumeOpts {
	return repository.ChallengeConsumeOpts{
		AcceptToken:  acceptToken,
		RequireToken: strict,
	}
}

func newRawSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func buildConsentUIURL(base, challengeID string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse consent url: %w", err)
	}
	q := u.Query()
	q.Set("consent_challenge", challengeID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildASVerifierURL(issuer string, kind domain.FlowVerifierKind, id uuid.UUID) string {
	return issuer + "/oauth2/auth?" + kind.QueryParam() + "=" + id.String()
}

func buildClientCallbackURL(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildClientErrorURL(redirectURI, state, errCode, desc, hint string) (string, error) {
	if errCode == "" {
		errCode = "access_denied"
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect_uri: %w", err)
	}
	q := u.Query()
	q.Set("error", errCode)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if hint != "" {
		q.Set("error_hint", hint)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ClientErrorRedirectURL builds a client redirect with OAuth error query params.
func ClientErrorRedirectURL(redirectURI, state, errCode, desc, hint string) (string, error) {
	return buildClientErrorURL(redirectURI, state, errCode, desc, hint)
}

func sessionExpiry(remember bool, rememberFor int64, defaultTTL, maxTTL time.Duration) time.Time {
	now := time.Now().UTC()
	if !remember {
		if defaultTTL <= 0 {
			defaultTTL = 24 * time.Hour
		}
		return now.Add(defaultTTL)
	}
	if rememberFor > 0 {
		d := time.Duration(rememberFor) * time.Second
		if maxTTL > 0 && d > maxTTL {
			d = maxTTL
		}
		return now.Add(d)
	}
	if maxTTL > 0 {
		return now.Add(maxTTL)
	}
	return now.Add(720 * time.Hour)
}

func mapChallengeErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, domain.ErrLoginChallengeNotFound),
		errors.Is(err, domain.ErrConsentChallengeNotFound):
		return fmt.Errorf("%w: %v", ErrChallengeNotFound, err)
	case errors.Is(err, domain.ErrLoginChallengeExpired),
		errors.Is(err, domain.ErrConsentChallengeExpired):
		return fmt.Errorf("%w: %v", ErrChallengeExpired, err)
	case errors.Is(err, domain.ErrLoginChallengeAcceptTokenInvalid),
		errors.Is(err, domain.ErrConsentChallengeAcceptTokenInvalid):
		return fmt.Errorf("%w: %v", ErrAcceptTokenInvalid, err)
	default:
		return err
	}
}
