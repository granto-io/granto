package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrUserNotFound is returned when a user does not exist.
	ErrUserNotFound = errors.New("user not found")
	// ErrEmailTaken is returned when creating a user with an existing email.
	ErrEmailTaken = errors.New("email already taken")
	// ErrPasswordNotSet is returned when verifying a password for a user
	// that has none (e.g. an email-OTP-only account).
	ErrPasswordNotSet = errors.New("password not set")
	// ErrInvalidPassword is returned when the password does not match.
	ErrInvalidPassword = errors.New("invalid password")
)

// User is an identity record.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// HasPassword reports whether the user has a stored password credential.
func (u *User) HasPassword() bool {
	return u.PasswordHash != ""
}
