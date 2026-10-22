package public

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/granto-io/granto/core/internal/config"
)

func TestAuthorizeRequestURLUsesIssuerNotHostHeaders(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, &config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example"},
	}, nil, nil, nil)

	r := httptest.NewRequest(http.MethodGet, "/oauth2/auth?client_id=app-a&state=s1", nil)
	r.Host = "evil.example"
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "evil.example")

	got := h.authorizeRequestURL(r)
	want := "https://auth.example/oauth2/auth?client_id=app-a&state=s1"
	if got != want {
		t.Fatalf("authorizeRequestURL = %q, want %q", got, want)
	}
}

func TestAuthorizeRequestURLTrimsIssuerSlash(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, &config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example/"},
	}, nil, nil, nil)

	r := httptest.NewRequest(http.MethodGet, "/oauth2/auth?foo=1", nil)
	r.Host = "ignored.example"

	got := h.authorizeRequestURL(r)
	want := "https://auth.example/oauth2/auth?foo=1"
	if got != want {
		t.Fatalf("authorizeRequestURL = %q, want %q", got, want)
	}
}

func TestAuthorizeRequestURLIgnoresAbsoluteRequestURIShape(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, &config.Config{
		Token: config.TokenConfig{Issuer: "https://auth.example"},
	}, nil, nil, nil)

	// EscapedPath is path-only; even if a proxy rewrites oddly, we never
	// echo an attacker-controlled absolute URL as request_url.
	r := httptest.NewRequest(http.MethodGet, "https://evil.example/oauth2/auth?x=1", nil)
	got := h.authorizeRequestURL(r)
	if got != "https://auth.example/oauth2/auth?x=1" {
		t.Fatalf("authorizeRequestURL = %q", got)
	}
}
