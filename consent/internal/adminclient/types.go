// Package adminclient is the consent service's typed client for the core
// Admin OAuth2Service.
//
// The engine depends on the Client interface, so core protobuf types never
// leak into the orchestration/plugin layers.
package adminclient

import "context"

// LoginRequest is a core login challenge as needed by the consent UI.
type LoginRequest struct {
	ChallengeID string
	ClientID    string
	RequestURL  string
	RedirectURI string

	RequestedScope    []string
	RequestedAudience []string
	Skip              bool

	Subject   string
	SessionID string

	LoginHint string

	// AcceptToken is required on Accept/Reject only when core runs in strict
	// accept mode. It is never exposed to plugins.
	AcceptToken string
}

// ConsentRequest is a core consent challenge as needed by the consent UI.
type ConsentRequest struct {
	ChallengeID string
	ClientID    string
	RequestURL  string
	RedirectURI string

	RequestedScope    []string
	RequestedAudience []string
	Skip              bool

	Subject   string
	SessionID string

	LoginChallengeID string
	ACR              string
	AMR              []string

	LoginHint string

	AcceptToken string
}

// AcceptLoginInput is the payload for accepting a login challenge.
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

// AcceptConsentInput is the payload for accepting a consent challenge.
type AcceptConsentInput struct {
	ChallengeID   string
	GrantScope    []string
	GrantScopeSet bool
	Remember      bool
	RememberFor   int64
	AcceptToken   string
}

// RejectInput is shared by login and consent rejection.
type RejectInput struct {
	ChallengeID      string
	Error            string
	ErrorDescription string
	ErrorHint        string
	AcceptToken      string
}

// Client calls the core Admin OAuth2Service.
type Client interface {
	GetLogin(ctx context.Context, challengeID string) (*LoginRequest, error)
	AcceptLogin(ctx context.Context, in AcceptLoginInput) (redirectTo string, err error)
	RejectLogin(ctx context.Context, in RejectInput) (redirectTo string, err error)

	GetConsent(ctx context.Context, challengeID string) (*ConsentRequest, error)
	AcceptConsent(ctx context.Context, in AcceptConsentInput) (redirectTo string, err error)
	RejectConsent(ctx context.Context, in RejectInput) (redirectTo string, err error)

	Close() error
}
