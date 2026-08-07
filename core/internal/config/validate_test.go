package config

import (
	"strings"
	"testing"
)

func TestSplitComma(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b , ", []string{"a", "b"}},
		{"  one  ", []string{"one"}},
	}
	for _, tc := range cases {
		got := splitComma(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("splitComma(%q)=%#v want %#v", tc.in, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("splitComma(%q)=%#v want %#v", tc.in, got, tc.want)
			}
		}
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	valid := func() *Config {
		cfg := defaults()
		cfg.Token.Issuer = "https://issuer"
		cfg.Token.MasterKey = strings.Repeat("x", 32)
		cfg.Postgres.DSN = "postgres://db"
		cfg.Admin.Token = "admin"
		cfg.OAuth2.LoginURL = "https://login"
		return cfg
	}

	if err := validate(valid()); err != nil {
		t.Fatalf("valid: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"issuer", func(c *Config) { c.Token.Issuer = "" }, "token.issuer"},
		{"master_key empty", func(c *Config) { c.Token.MasterKey = "" }, "token.master_key is required"},
		{"master_key short", func(c *Config) { c.Token.MasterKey = "short" }, "at least 32"},
		{"dsn", func(c *Config) { c.Postgres.DSN = "" }, "postgres.dsn"},
		{"admin", func(c *Config) { c.Admin.Token = "" }, "admin.token"},
		{"login", func(c *Config) { c.OAuth2.LoginURL = "" }, "oauth2.login_url"},
	}
	for _, tc := range cases {
		cfg := valid()
		tc.mutate(cfg)
		err := validate(cfg)
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Fatalf("%s: got %v, want substring %q", tc.name, err, tc.wantSub)
		}
	}
}
