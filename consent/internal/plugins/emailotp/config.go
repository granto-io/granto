// Package emailotp is the built-in email one-time-code login plugin.
//
// Flow: the user submits an email address, the plugin resolves/creates the
// user through its identity backend (a stub for now), delivers a 6-digit
// code through its mailer (log-only dev stub), and verifies the code. On
// success the engine accepts the login challenge in core and the browser
// continues the OAuth2 flow.
package emailotp

import (
	"errors"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is plugins.config.email-otp.
type Config struct {
	// DevLogCodes writes generated codes to the service log. Never enable
	// this outside local development.
	DevLogCodes bool `yaml:"dev_log_codes"`
	// CodeTTL is how long a code stays valid.
	CodeTTL time.Duration `yaml:"code_ttl"`
	// MaxAttempts is the number of wrong codes allowed per challenge.
	MaxAttempts int `yaml:"max_attempts"`
	// ResendCooldown is the minimum delay between two send requests for the
	// same challenge.
	ResendCooldown time.Duration `yaml:"resend_cooldown"`
}

func defaultConfig() Config {
	return Config{
		CodeTTL:        10 * time.Minute,
		MaxAttempts:    5,
		ResendCooldown: time.Minute,
	}
}

func parseConfig(node *yaml.Node) (Config, error) {
	cfg := defaultConfig()
	if node != nil && node.Kind != 0 && (node.Kind != yaml.ScalarNode || node.Tag != "!!null") {
		if err := node.Decode(&cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.CodeTTL <= 0 {
		return Config{}, errors.New("email-otp: code_ttl must be positive")
	}
	if cfg.MaxAttempts <= 0 {
		return Config{}, errors.New("email-otp: max_attempts must be positive")
	}
	if cfg.ResendCooldown < 0 {
		return Config{}, errors.New("email-otp: resend_cooldown must not be negative")
	}
	if cfg.ResendCooldown > cfg.CodeTTL {
		return Config{}, errors.New("email-otp: resend_cooldown must not exceed code_ttl")
	}
	return cfg, nil
}
