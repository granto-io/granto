package public_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/granto-io/granto/consent/internal/transport/public"
)

func TestRouter_StubEndpoints(t *testing.T) {
	t.Parallel()
	router := public.NewRouter(nil, public.Options{})

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/login"},
		{http.MethodPost, "/login"},
		{http.MethodGet, "/consent"},
		{http.MethodPost, "/consent"},
	} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s: status=%d, want 501", tc.method, tc.path, rr.Code)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("%s %s: Cache-Control=%q, want no-store", tc.method, tc.path, cc)
		}
	}
}
