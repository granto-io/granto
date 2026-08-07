package domain

import "errors"

var (
	ErrClientNotFound       = errors.New("client not found")
	ErrLoginSessionNotFound = errors.New("login session not found")
)
