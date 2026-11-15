// Package pluginapi is the public contract between the consent engine and
// login plugins.
//
// A plugin is compiled into the consent binary (see Register) and activated
// at runtime by name via plugins.enabled. The engine owns challenge
// validation, CSRF enforcement, and the call to the core Admin API; the
// plugin owns its login UI and credential checks.
package pluginapi

import (
	"context"
	"errors"
	"log/slog"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// Kind describes how a plugin interacts with the browser.
type Kind string

const (
	// FormKind plugins render their own HTML forms under Host.Router.
	FormKind Kind = "form"
	// RedirectKind plugins redirect the browser to an external provider.
	// Reserved for future providers (Google, SMS gateways, etc.).
	RedirectKind Kind = "redirect"
)

// Plugin is a login method.
type Plugin interface {
	// Name is the registration name (plugins.enabled uses it).
	Name() string
	// DisplayName is shown on the login method chooser.
	DisplayName() string
	// Kind is the interaction model.
	Kind() Kind
	// Init wires the plugin to the engine. The plugin registers its routes
	// on Host.Router and keeps the host for later calls.
	Init(host Host) error
}

// Host is the engine surface available to plugins.
//
// CompleteLogin and RejectLogin verify the CSRF token themselves; a plugin
// cannot bypass challenge-bound CSRF protection by forgetting the check.
type Host interface {
	Logger() *slog.Logger
	// Config returns this plugin's YAML node from plugins.config.<name>.
	// It is a mapping node (possibly empty) that the plugin may Decode.
	Config() *yaml.Node
	// Router is mounted at /login/<plugin-name>; register relative paths.
	Router() chi.Router
	// CSRFToken returns the token to embed in a hidden form field for the
	// given challenge.
	CSRFToken(challengeID string) string
	// VerifyCSRF checks a token submitted from the browser. Call it before
	// any side effect (sending an email, checking a code).
	VerifyCSRF(challengeID, token string) error
	// GetLogin loads and validates a login challenge. Use it on GET to
	// render the form and to prefill known hints.
	GetLogin(ctx context.Context, challengeID string) (*LoginRequest, error)
	// CompleteLogin accepts the challenge in core and returns the redirect
	// target (the OAuth2 flow continues there).
	CompleteLogin(ctx context.Context, in LoginCompletion) (redirectTo string, err error)
	// RejectLogin rejects the challenge in core and returns the redirect
	// target (usually the client with an OAuth2 error).
	RejectLogin(ctx context.Context, in LoginRejection) (redirectTo string, err error)
	// Identity returns the identity backend client. Plugins that need to
	// resolve or create users (email-OTP, password) use it instead of
	// talking to a storage directly. The engine wires it from the configured
	// identity service address; a nil client means no identity backend is
	// configured and such plugins must fail Init.
	Identity() IdentityClient
}

// IdentityClient is the identity backend contract exposed to plugins.
//
// It mirrors the identity service's public gRPC contract (IdentityService)
// so a plugin stays decoupled from the transport. The engine provides a
// gRPC-backed implementation; third-party identity backends can be plugged
// in by implementing this interface.
type IdentityClient interface {
	// GetOrCreateUserByEmail resolves an email to a user, creating a
	// password-less user when missing. Returns the user id and normalized
	// email.
	GetOrCreateUserByEmail(ctx context.Context, email string) (userID, normalizedEmail string, err error)
}

// LoginRequest is the plugin-facing view of a core login challenge.
type LoginRequest struct {
	ChallengeID string
	ClientID    string
	// LoginHint is the OIDC login_hint, when supplied by the client.
	LoginHint string
	// Subject is the already-authenticated subject (SSO), when present.
	Subject string
}

// LoginCompletion is the successful authentication result.
type LoginCompletion struct {
	ChallengeID string
	CSRFToken   string
	Subject     string
	Remember    bool
	RememberFor int64
	ACR         string
	AMR         []string
	// Context is stored on the consent challenge for downstream use.
	Context map[string]any
	// IdentityProviderSessionID links an external identity session.
	IdentityProviderSessionID string
}

// LoginRejection aborts the flow with an OAuth2 error.
type LoginRejection struct {
	ChallengeID      string
	CSRFToken        string
	Error            string
	ErrorDescription string
	ErrorHint        string
}

var (
	// ErrInvalidCSRF is returned when the form token does not match the
	// challenge.
	ErrInvalidCSRF = errors.New("pluginapi: invalid csrf token")
	// ErrMissingSubject is returned by CompleteLogin without a subject.
	ErrMissingSubject = errors.New("pluginapi: subject is required")
	// ErrUnsupportedKind is returned when the engine cannot run a plugin kind.
	ErrUnsupportedKind = errors.New("pluginapi: unsupported plugin kind")
)
