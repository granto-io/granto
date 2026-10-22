package public

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestLogoutGETShowsConfirmForBroadScope(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Token:   config.TokenConfig{Issuer: "https://auth.example"},
		Session: config.SessionConfig{LogoutScope: config.LogoutScopeSubject, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	flow := oauth2.NewFlow(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := NewHandler(nil, cfg, flow, nil, nil)
	mux := NewRouter(h, Options{})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?client_id=app-a&state=s1&post_logout_redirect_uri=https://app.example/bye", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `method="post"`) || !strings.Contains(body, `action="/oauth2/logout"`) {
		t.Fatalf("expected confirm form, got: %s", body)
	}
	if !strings.Contains(body, `name="client_id"`) || !strings.Contains(body, `value="app-a"`) {
		t.Fatalf("expected preserved client_id, got: %s", body)
	}
	if !strings.Contains(body, `name="state"`) || !strings.Contains(body, `value="s1"`) {
		t.Fatalf("expected preserved state, got: %s", body)
	}
	if ct := rr.Header().Get("Cache-Control"); ct != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", ct)
	}
}

func TestLogoutGETSessionScopeDoesNotConfirm(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Token:   config.TokenConfig{Issuer: "https://auth.example"},
		Session: config.SessionConfig{LogoutScope: config.LogoutScopeSession, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	flow := oauth2.NewFlow(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := NewHandler(slog.Default(), cfg, flow, nil, nil)
	mux := NewRouter(h, Options{})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Confirm sign-out") {
		t.Fatal("session scope must not show confirm page")
	}
	if got := rr.Body.String(); got != "Logged out" {
		t.Fatalf("body=%q, want Logged out", got)
	}
}

func TestLogoutGETSessionScopeConfirmOnCrossSiteWithoutHint(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Token:   config.TokenConfig{Issuer: "https://auth.example"},
		Session: config.SessionConfig{LogoutScope: config.LogoutScopeSession, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	flow := oauth2.NewFlow(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := NewHandler(slog.Default(), cfg, flow, nil, nil)
	mux := NewRouter(h, Options{})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Confirm sign-out") {
		t.Fatalf("cross-site cookie-only GET must confirm, got: %s", rr.Body.String())
	}
}

func TestLogoutGETSessionScopeAllowsCrossSiteWithIDTokenHint(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		Token:   config.TokenConfig{Issuer: "https://auth.example"},
		Session: config.SessionConfig{LogoutScope: config.LogoutScopeSession, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour},
	}
	flow := oauth2.NewFlow(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	h := NewHandler(slog.Default(), cfg, flow, nil, nil)
	mux := NewRouter(h, Options{})

	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?id_token_hint=eyJhbGciOiJub25lIn0.e30.", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Confirm sign-out") {
		t.Fatal("RP-initiated cross-site GET with id_token_hint must not force confirm")
	}
	if got := rr.Body.String(); got != "Logged out" {
		t.Fatalf("body=%q, want Logged out", got)
	}
}
