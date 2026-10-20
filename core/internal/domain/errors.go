package domain

import "errors"

var (
	ErrClientNotFound                     = errors.New("client not found")
	ErrLoginSessionNotFound               = errors.New("login session not found")
	ErrLoginChallengeNotFound             = errors.New("login challenge not found")
	ErrLoginChallengeExpired              = errors.New("login challenge expired")
	ErrLoginChallengeAcceptTokenInvalid   = errors.New("login challenge accept token invalid")
	ErrConsentChallengeNotFound           = errors.New("consent challenge not found")
	ErrConsentChallengeExpired            = errors.New("consent challenge expired")
	ErrConsentChallengeAcceptTokenInvalid = errors.New("consent challenge accept token invalid")
	ErrFlowVerifierNotFound               = errors.New("flow verifier not found")
	ErrFlowVerifierExpired                = errors.New("flow verifier expired")
	ErrAuthorizationCodeNotFound          = errors.New("authorization code not found")
	ErrAuthorizationCodeExpired           = errors.New("authorization code expired")
	ErrAuthorizationCodeUsed              = errors.New("authorization code already used")
	ErrAccessTokenNotFound                = errors.New("access token not found")
	ErrAccessTokenExpired                 = errors.New("access token expired")
	ErrRefreshTokenNotFound               = errors.New("refresh token not found")
	ErrRefreshTokenExpired                = errors.New("refresh token expired")
	ErrSigningKeyNotFound                 = errors.New("signing key not found")
)
