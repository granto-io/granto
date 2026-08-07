package domain

import "errors"

var (
	ErrClientNotFound                   = errors.New("client not found")
	ErrLoginSessionNotFound             = errors.New("login session not found")
	ErrLoginChallengeNotFound           = errors.New("login challenge not found")
	ErrLoginChallengeExpired            = errors.New("login challenge expired")
	ErrLoginChallengeAcceptTokenInvalid = errors.New("login challenge accept token invalid")
)
