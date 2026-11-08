// Package config loads granto-consent settings: defaults → optional YAML → env overrides.
package config

import "time"

// Config is the root configuration for granto-consent.
type Config struct {
	Server ServerConfig `yaml:"server"`
	Log    LogConfig    `yaml:"log"`
}

// ServerConfig holds the listen address and process lifecycle settings.
type ServerConfig struct {
	Addr            string        `yaml:"addr"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

// LogConfig controls the process logger.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}
