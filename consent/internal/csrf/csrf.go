// Package csrf issues and verifies tokens bound to a single login/consent
// challenge.
//
// The token is an HMAC of the challenge id, so it survives across requests
// and processes without server-side storage. The secret must be shared
// between replicas, otherwise a token issued by one instance is rejected
// by another.
package csrf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidToken is returned when a token is missing or does not match the
// challenge.
var ErrInvalidToken = errors.New("invalid csrf token")

const contextPrefix = "consent-csrf:v1:"

// Service issues and verifies challenge-bound CSRF tokens.
type Service struct {
	key []byte
}

// New builds a Service. An empty secret generates a random per-process key.
func New(secret string) *Service {
	key := []byte(strings.TrimSpace(secret))
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// crypto/rand failure is not recoverable for a security primitive.
			panic(fmt.Sprintf("csrf: read random key: %v", err))
		}
	}
	return &Service{key: key}
}

// Token returns the CSRF token for a challenge id.
func (s *Service) Token(challengeID string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(contextPrefix + strings.TrimSpace(challengeID)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports whether token belongs to challengeID.
func (s *Service) Verify(challengeID, token string) error {
	challengeID = strings.TrimSpace(challengeID)
	token = strings.TrimSpace(token)
	if challengeID == "" || token == "" {
		return ErrInvalidToken
	}
	want := s.Token(challengeID)
	if !hmac.Equal([]byte(want), []byte(token)) {
		return ErrInvalidToken
	}
	return nil
}
