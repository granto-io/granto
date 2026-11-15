package emailotp

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

var (
	// ErrCooldown means a code was sent too recently for this challenge.
	ErrCooldown = errors.New("email-otp: code cooldown")
	// ErrCodeNotFound means no code was requested for this challenge.
	ErrCodeNotFound = errors.New("email-otp: code not found")
	// ErrCodeExpired means the code's TTL has passed.
	ErrCodeExpired = errors.New("email-otp: code expired")
	// ErrCodeMismatch means the submitted code is wrong.
	ErrCodeMismatch = errors.New("email-otp: code mismatch")
	// ErrTooManyAttempts means the challenge's attempt budget is exhausted.
	ErrTooManyAttempts = errors.New("email-otp: too many attempts")
)

// pendingCode is the per-challenge OTP state.
type pendingCode struct {
	email      string
	subject    string
	code       string
	expiresAt  time.Time
	lastSentAt time.Time
	attempts   int
}

// codeStore keeps pending codes in memory.
//
// The MVP runs a single consent instance; multi-instance deployments need a
// shared store (Redis) before this plugin can be scaled out.
type codeStore struct {
	mu          sync.Mutex
	now         func() time.Time
	byChallenge map[string]*pendingCode
}

func newCodeStore(now func() time.Time) *codeStore {
	if now == nil {
		now = time.Now
	}
	return &codeStore{now: now, byChallenge: make(map[string]*pendingCode)}
}

// issue creates (or rotates) the code for a challenge. It returns ErrCooldown
// while the previous code is still cooling down.
func (s *codeStore) issue(challengeID, email, subject string, ttl, cooldown time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	// Lazy GC: drop expired entries so abandoned challenges do not leak.
	for id, p := range s.byChallenge {
		if !now.Before(p.expiresAt) {
			delete(s.byChallenge, id)
		}
	}
	if p, ok := s.byChallenge[challengeID]; ok {
		if now.Before(p.expiresAt) && now.Sub(p.lastSentAt) < cooldown {
			return "", ErrCooldown
		}
	}

	code, err := randomCode()
	if err != nil {
		return "", err
	}
	s.byChallenge[challengeID] = &pendingCode{
		email:      email,
		subject:    subject,
		code:       code,
		expiresAt:  now.Add(ttl),
		lastSentAt: now,
	}
	return code, nil
}

// verify checks a submitted code (and the email it was issued for) and
// returns the subject on success.
func (s *codeStore) verify(challengeID, email, code string, maxAttempts int) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.byChallenge[challengeID]
	if !ok {
		return "", ErrCodeNotFound
	}
	if !s.now().UTC().Before(p.expiresAt) {
		delete(s.byChallenge, challengeID)
		return "", ErrCodeExpired
	}
	if p.attempts >= maxAttempts {
		delete(s.byChallenge, challengeID)
		return "", ErrTooManyAttempts
	}
	// The code is bound to the email it was issued for; a mismatch means the
	// form was tampered with and must not consume an attempt budget.
	if subtle.ConstantTimeCompare([]byte(p.email), []byte(email)) != 1 {
		return "", ErrCodeMismatch
	}
	if subtle.ConstantTimeCompare([]byte(p.code), []byte(code)) != 1 {
		p.attempts++
		if p.attempts >= maxAttempts {
			delete(s.byChallenge, challengeID)
			return "", ErrTooManyAttempts
		}
		return "", ErrCodeMismatch
	}

	delete(s.byChallenge, challengeID)
	return p.subject, nil
}

func (s *codeStore) discard(challengeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byChallenge, challengeID)
}

func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("email-otp: generate code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
