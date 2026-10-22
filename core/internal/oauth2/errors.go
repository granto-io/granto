package oauth2

import "errors"

var (
	ErrInvalidRequest          = errors.New("invalid request")
	ErrChallengeNotFound       = errors.New("challenge not found")
	ErrChallengeExpired        = errors.New("challenge expired")
	ErrAcceptTokenInvalid      = errors.New("accept token invalid")
	ErrInvalidClient           = errors.New("invalid client")
	ErrInvalidRedirectURI      = errors.New("invalid redirect_uri")
	ErrUnsupportedResponseType = errors.New("unsupported response_type")
	ErrInvalidScope            = errors.New("invalid scope")
	ErrPKCERequired            = errors.New("pkce required")
	ErrVerifierNotFound        = errors.New("flow verifier not found")
	ErrVerifierExpired         = errors.New("flow verifier expired")
	ErrInvalidClientSecret     = errors.New("invalid client credentials")
	ErrInvalidGrant            = errors.New("invalid grant")
	ErrInvalidCodeVerifier     = errors.New("invalid code_verifier")
	ErrUnauthorizedClient      = errors.New("unauthorized client")
	ErrTokenNotFound           = errors.New("token not found")
	ErrSessionExpired          = errors.New("session expired")
)

// ClientRedirectError is an authorize error that must be returned to the client
// via redirect to a previously validated redirect_uri (RFC 6749 §4.1.2.1).
// Do not use for invalid client_id / redirect_uri — those must not redirect.
type ClientRedirectError struct {
	Err         error
	RedirectURI string
	State       string
}

func (e *ClientRedirectError) Error() string {
	if e == nil || e.Err == nil {
		return "authorize redirect error"
	}
	return e.Err.Error()
}

func (e *ClientRedirectError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func clientRedirect(err error, redirectURI, state string) error {
	if err == nil {
		return nil
	}
	return &ClientRedirectError{Err: err, RedirectURI: redirectURI, State: state}
}
