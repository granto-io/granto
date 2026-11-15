package public_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/csrf"
	"github.com/granto-io/granto/consent/internal/engine"
	"github.com/granto-io/granto/consent/internal/transport/public"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

type stubPlugin struct{}

func (stubPlugin) Name() string        { return "stub" }
func (stubPlugin) DisplayName() string { return "Stub login" }
func (stubPlugin) Kind() pluginapi.Kind {
	return pluginapi.FormKind
}
func (stubPlugin) Init(host pluginapi.Host) error {
	host.Router().Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return nil
}

// stubAdmin embeds the interface so unused methods stay out of the test.
type stubAdmin struct {
	adminclient.Client
	consent *adminclient.ConsentRequest
}

func (s *stubAdmin) GetConsent(context.Context, string) (*adminclient.ConsentRequest, error) {
	return s.consent, nil
}

func (s *stubAdmin) Close() error { return nil }

func newRouter(t *testing.T) http.Handler {
	t.Helper()

	registry := pluginapi.NewRegistry()
	registry.Register("stub", func() pluginapi.Plugin { return stubPlugin{} })

	eng, err := engine.New(engine.Options{
		Admin:   &stubAdmin{consent: &adminclient.ConsentRequest{ClientID: "demo-client", RequestedScope: []string{"openid", "profile"}}},
		CSRF:    csrf.New("test-secret"),
		Plugins: registry,
		Enabled: []string{"stub"},
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	router, err := public.NewRouter(eng, public.Options{})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return router
}

func TestNewRouter_RequiresEngine(t *testing.T) {
	t.Parallel()

	if _, err := public.NewRouter(nil, public.Options{}); err == nil {
		t.Fatal("NewRouter(nil): expected error")
	}
}

func TestRouter_LoginRedirectsToSinglePlugin(t *testing.T) {
	t.Parallel()
	router := newRouter(t)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login?login_challenge=ch-1", nil))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303", rr.Code)
	}
	if got, want := rr.Header().Get("Location"), "/login/stub?login_challenge=ch-1"; got != want {
		t.Fatalf("Location=%q, want %q", got, want)
	}
	assertBrowserHardening(t, rr)
}

func TestRouter_ConsentPage(t *testing.T) {
	t.Parallel()
	router := newRouter(t)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=ch-2", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"demo-client", "openid", "profile", `name="csrf_token"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body does not contain %q", want)
		}
	}
	assertBrowserHardening(t, rr)
}

func TestRouter_ConsentRejectsMissingCSRF(t *testing.T) {
	t.Parallel()
	router := newRouter(t)

	form := "consent_challenge=ch-2&decision=accept"
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	assertBrowserHardening(t, rr)
}

func assertBrowserHardening(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
	if pragma := rr.Header().Get("Pragma"); pragma != "no-cache" {
		t.Fatalf("Pragma=%q, want no-cache", pragma)
	}
	if xfo := rr.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Fatalf("X-Frame-Options=%q, want DENY", xfo)
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy=%q, want frame-ancestors 'none'", csp)
	}
}
