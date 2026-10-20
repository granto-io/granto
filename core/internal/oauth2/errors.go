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
