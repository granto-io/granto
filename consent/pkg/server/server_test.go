package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/granto-io/granto/consent/internal/transport/public"
)

func TestNewMux_Health(t *testing.T) {
	t.Parallel()

	mux := newMux(public.NewRouter(nil, public.Options{}))

	for _, tc := range []struct {
		method     string
		path       string
		wantStatus int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		// Non-GET requests do not match the method-scoped health pattern and
		// fall through to the protocol router, which does not know the path.
		{http.MethodPost, "/health", http.StatusNotFound},
		{http.MethodGet, "/login", http.StatusNotImplemented},
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != tc.wantStatus {
			t.Fatalf("%s %s: status=%d, want %d", tc.method, tc.path, rr.Code, tc.wantStatus)
		}
	}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if got, want := rr.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("Content-Type=%q, want %q", got, want)
	}
	if got, want := rr.Body.String(), `{"status":"ok"}`; got != want {
		t.Fatalf("body=%q, want %q", got, want)
	}
}
