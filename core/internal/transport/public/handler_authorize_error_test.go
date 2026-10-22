package public

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/granto-io/granto/core/internal/oauth2"
)

func TestWriteAuthorizeErrorClientRedirect(t *testing.T) {
	t.Parallel()
	h := NewHandler(slog.Default(), nil, nil, nil, nil)

	err := &oauth2.ClientRedirectError{
		Err:         oauth2.ErrInvalidScope,
		RedirectURI: "https://app.example/cb",
		State:       "xyz",
	}
	rec := httptest.NewRecorder()
	h.writeAuthorizeError(rec, err)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	u, parseErr := url.Parse(loc)
	if parseErr != nil {
		t.Fatalf("Location parse: %v (%q)", parseErr, loc)
	}
	q := u.Query()
	if q.Get("error") != "invalid_scope" {
		t.Fatalf("error = %q, want invalid_scope; loc=%q", q.Get("error"), loc)
	}
	if q.Get("state") != "xyz" {
		t.Fatalf("state = %q, want xyz", q.Get("state"))
	}
	if u.Scheme != "https" || u.Host != "app.example" || u.Path != "/cb" {
		t.Fatalf("Location base = %q", loc)
	}
}

func TestWriteAuthorizeErrorPKCERequiredRedirect(t *testing.T) {
	t.Parallel()
	h := NewHandler(slog.Default(), nil, nil, nil, nil)

	err := &oauth2.ClientRedirectError{
		Err:         oauth2.ErrPKCERequired,
		RedirectURI: "https://app.example/cb",
		State:       "s1",
	}
	rec := httptest.NewRecorder()
	h.writeAuthorizeError(rec, err)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("Location = %q, want error=invalid_request (pkce_required)", loc)
	}
	if !strings.Contains(loc, "state=s1") {
		t.Fatalf("Location = %q, want state=s1", loc)
	}
}

func TestWriteAuthorizeErrorInvalidRedirectURIJSON(t *testing.T) {
	t.Parallel()
	h := NewHandler(slog.Default(), nil, nil, nil, nil)

	rec := httptest.NewRecorder()
	h.writeAuthorizeError(rec, oauth2.ErrInvalidRedirectURI)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("must not redirect, got Location=%q", loc)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "invalid_request") && !strings.Contains(body, "invalid_redirect") {
		// oauthErrorCode maps unknown / invalid_redirect_uri to invalid_request
		t.Fatalf("body = %q, want OAuth JSON error", body)
	}
}
