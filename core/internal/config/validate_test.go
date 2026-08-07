package config

import (
	"strings"
	"testing"
)

func TestSplitComma(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "single token", in: "a", want: []string{"a"}},
		{name: "two tokens", in: "a,b", want: []string{"a", "b"}},
		{name: "trims spaces and drops empties", in: " a , b , ", want: []string{"a", "b"}},
		{name: "trims single token", in: "  one  ", want: []string{"one"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitComma(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("splitComma(%q) = %#v (len %d), want %#v (len %d)", tc.in, got, len(got), tc.want, len(tc.want))
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("splitComma(%q) = %#v, want %#v", tc.in, got, tc.want)
				}
			}
		})
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

	t.Run("complete config is valid", func(t *testing.T) {
		if err := validate(valid()); err != nil {
			t.Fatalf("validate(complete config) = %v, want nil", err)
		}
	})

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{name: "missing issuer", mutate: func(c *Config) { c.Token.Issuer = "" }, wantSub: "token.issuer"},
		{name: "missing master key", mutate: func(c *Config) { c.Token.MasterKey = "" }, wantSub: "token.master_key is required"},
		{name: "short master key", mutate: func(c *Config) { c.Token.MasterKey = "short" }, wantSub: "at least 32"},
		{name: "missing postgres dsn", mutate: func(c *Config) { c.Postgres.DSN = "" }, wantSub: "postgres.dsn"},
		{name: "missing admin token", mutate: func(c *Config) { c.Admin.Token = "" }, wantSub: "admin.token"},
		{name: "missing login url", mutate: func(c *Config) { c.OAuth2.LoginURL = "" }, wantSub: "oauth2.login_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			err := validate(cfg)
			if err == nil {
				t.Fatalf("validate(%s) = nil, want error containing %q", tc.name, tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("validate(%s) error = %q, want substring %q", tc.name, err.Error(), tc.wantSub)
			}
		})
	}
}
