package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthMux(t *testing.T) {
	t.Parallel()

	a := &App{Public: http.NotFoundHandler()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.Handle("/", a.Public)

	for _, tc := range []struct {
		method     string
		path       string
		wantStatus int
	}{
		{http.MethodGet, "/health", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusNotFound},
		{http.MethodPost, "/health", http.StatusNotFound},
		{http.MethodGet, "/login", http.StatusNotFound},
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
