package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/granto-io/granto/consent/internal/adminclient"
	"github.com/granto-io/granto/consent/internal/csrf"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

type fakeAdmin struct {
	adminclient.Client

	login   *adminclient.LoginRequest
	consent *adminclient.ConsentRequest
	err     error

	acceptLoginIn   adminclient.AcceptLoginInput
	rejectLoginIn   adminclient.RejectInput
	acceptConsentIn adminclient.AcceptConsentInput
	rejectConsentIn adminclient.RejectInput
	adminCalls      int
}

func (f *fakeAdmin) GetLogin(context.Context, string) (*adminclient.LoginRequest, error) {
	f.adminCalls++
	if f.err != nil {
		return nil, f.err
	}
	if f.login == nil {
		return nil, errors.New("no login request")
	}
	return f.login, nil
}

func (f *fakeAdmin) AcceptLogin(_ context.Context, in adminclient.AcceptLoginInput) (string, error) {
	f.adminCalls++
	if f.err != nil {
		return "", f.err
	}
	f.acceptLoginIn = in
	return "http://core.example/after-login", nil
}

func (f *fakeAdmin) RejectLogin(_ context.Context, in adminclient.RejectInput) (string, error) {
	f.adminCalls++
	if f.err != nil {
		return "", f.err
	}
	f.rejectLoginIn = in
	return "http://core.example/rejected", nil
}

func (f *fakeAdmin) GetConsent(context.Context, string) (*adminclient.ConsentRequest, error) {
	f.adminCalls++
	if f.err != nil {
		return nil, f.err
	}
	if f.consent == nil {
		return nil, errors.New("no consent request")
	}
	return f.consent, nil
}

func (f *fakeAdmin) AcceptConsent(_ context.Context, in adminclient.AcceptConsentInput) (string, error) {
	f.adminCalls++
	if f.err != nil {
		return "", f.err
	}
	f.acceptConsentIn = in
	return "http://client.example/callback?code=abc", nil
}

func (f *fakeAdmin) RejectConsent(_ context.Context, in adminclient.RejectInput) (string, error) {
	f.adminCalls++
	if f.err != nil {
		return "", f.err
	}
	f.rejectConsentIn = in
	return "http://client.example/callback?error=access_denied", nil
}

func (f *fakeAdmin) Close() error { return nil }

type testPlugin struct {
	name    string
	display string
}

func (p testPlugin) Name() string        { return p.name }
func (p testPlugin) DisplayName() string { return p.display }
func (p testPlugin) Kind() pluginapi.Kind {
	return pluginapi.FormKind
}
func (p testPlugin) Init(pluginapi.Host) error { return nil }

func newTestRegistry(names ...string) *pluginapi.Registry {
	r := pluginapi.NewRegistry()
	for _, name := range names {
		name := name
		r.Register(name, func() pluginapi.Plugin {
			return testPlugin{name: name, display: "Login via " + name}
		})
	}
	return r
}

func newTestEngine(t *testing.T, admin adminclient.Client, csrfSvc *csrf.Service, names ...string) *Engine {
	t.Helper()
	if csrfSvc == nil {
		csrfSvc = csrf.New("test-secret")
	}
	eng, err := New(Options{
		Admin:   admin,
		CSRF:    csrfSvc,
		Plugins: newTestRegistry(names...),
		Enabled: names,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return eng
}

func serve(eng *Engine, req *http.Request) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	if err := eng.RegisterRoutes(r); err != nil {
		panic(err)
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func postForm(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{}
	csrfSvc := csrf.New("test-secret")

	if _, err := New(Options{CSRF: csrfSvc, Plugins: newTestRegistry("a"), Enabled: []string{"a"}}); err == nil {
		t.Fatal("expected error without admin client")
	}
	if _, err := New(Options{Admin: admin, Plugins: newTestRegistry("a"), Enabled: []string{"a"}}); err == nil {
		t.Fatal("expected error without csrf service")
	}
	if _, err := New(Options{Admin: admin, CSRF: csrfSvc, Enabled: []string{"a"}}); err == nil {
		t.Fatal("expected error without registry")
	}
	if _, err := New(Options{Admin: admin, CSRF: csrfSvc, Plugins: newTestRegistry("a")}); err == nil {
		t.Fatal("expected error without enabled plugins")
	}
	if _, err := New(Options{Admin: admin, CSRF: csrfSvc, Plugins: newTestRegistry("a"), Enabled: []string{"missing"}}); err == nil {
		t.Fatal("expected error for unregistered plugin")
	}
	if _, err := New(Options{Admin: admin, CSRF: csrfSvc, Plugins: newTestRegistry("a"), Enabled: []string{"a", "a"}}); err == nil {
		t.Fatal("expected error for duplicate plugin")
	}
}

func TestLogin_RedirectsToSinglePlugin(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t, &fakeAdmin{}, nil, "email")
	rr := serve(eng, httptest.NewRequest(http.MethodGet, "/login?login_challenge=ch-1", nil))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303", rr.Code)
	}
	if got, want := rr.Header().Get("Location"), "/login/email?login_challenge=ch-1"; got != want {
		t.Fatalf("Location=%q, want %q", got, want)
	}
}

func TestLogin_ChooserForMultiplePlugins(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t, &fakeAdmin{}, nil, "email", "password")
	rr := serve(eng, httptest.NewRequest(http.MethodGet, "/login?login_challenge=ch-1", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Login via email", "Login via password", "/login/password?login_challenge=ch-1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body does not contain %q", want)
		}
	}
}

func TestLogin_MissingChallenge(t *testing.T) {
	t.Parallel()

	eng := newTestEngine(t, &fakeAdmin{}, nil, "email")
	rr := serve(eng, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestConsent_Accept(t *testing.T) {
	t.Parallel()

	csrfSvc := csrf.New("test-secret")
	admin := &fakeAdmin{consent: &adminclient.ConsentRequest{
		ChallengeID:    "ch-2",
		ClientID:       "demo",
		RequestedScope: []string{"openid", "profile"},
		AcceptToken:    "accept-token",
	}}
	eng := newTestEngine(t, admin, csrfSvc, "email")

	rr := serve(eng, postForm(t, url.Values{
		"consent_challenge": {"ch-2"},
		"csrf_token":        {csrfSvc.Token("ch-2")},
		"decision":          {"accept"},
		"remember":          {"1"},
	}))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303; body=%s", rr.Code, rr.Body.String())
	}
	if got, want := rr.Header().Get("Location"), "http://client.example/callback?code=abc"; got != want {
		t.Fatalf("Location=%q, want %q", got, want)
	}
	if !admin.acceptConsentIn.GrantScopeSet {
		t.Fatal("GrantScopeSet = false, want true")
	}
	if len(admin.acceptConsentIn.GrantScope) != 2 {
		t.Fatalf("GrantScope = %v, want requested scopes", admin.acceptConsentIn.GrantScope)
	}
	if !admin.acceptConsentIn.Remember {
		t.Fatal("Remember = false, want true")
	}
	if admin.acceptConsentIn.AcceptToken != "accept-token" {
		t.Fatalf("AcceptToken = %q, want accept-token", admin.acceptConsentIn.AcceptToken)
	}
}

func TestConsent_Reject(t *testing.T) {
	t.Parallel()

	csrfSvc := csrf.New("test-secret")
	admin := &fakeAdmin{consent: &adminclient.ConsentRequest{ChallengeID: "ch-2", ClientID: "demo", AcceptToken: "accept-token"}}
	eng := newTestEngine(t, admin, csrfSvc, "email")

	rr := serve(eng, postForm(t, url.Values{
		"consent_challenge": {"ch-2"},
		"csrf_token":        {csrfSvc.Token("ch-2")},
		"decision":          {"reject"},
	}))

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303", rr.Code)
	}
	if got, want := rr.Header().Get("Location"), "http://client.example/callback?error=access_denied"; got != want {
		t.Fatalf("Location=%q, want %q", got, want)
	}
	if admin.rejectConsentIn.Error != "access_denied" {
		t.Fatalf("Error = %q, want access_denied", admin.rejectConsentIn.Error)
	}
	if admin.rejectConsentIn.AcceptToken != "accept-token" {
		t.Fatalf("AcceptToken = %q, want accept-token", admin.rejectConsentIn.AcceptToken)
	}
}

func TestConsent_InvalidCSRF(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{}
	eng := newTestEngine(t, admin, nil, "email")

	rr := serve(eng, postForm(t, url.Values{
		"consent_challenge": {"ch-2"},
		"csrf_token":        {"wrong"},
		"decision":          {"accept"},
	}))

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if admin.adminCalls != 0 {
		t.Fatalf("admin calls = %d, want 0", admin.adminCalls)
	}
}

func TestConsent_ExpiredChallenge(t *testing.T) {
	t.Parallel()

	csrfSvc := csrf.New("test-secret")
	admin := &fakeAdmin{err: errors.New("challenge not found")}
	eng := newTestEngine(t, admin, csrfSvc, "email")

	rr := serve(eng, httptest.NewRequest(http.MethodGet, "/consent?consent_challenge=ch-2", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestHost_CompleteLogin(t *testing.T) {
	t.Parallel()

	csrfSvc := csrf.New("test-secret")
	admin := &fakeAdmin{login: &adminclient.LoginRequest{ChallengeID: "ch-3", AcceptToken: "accept-token"}}
	eng := newTestEngine(t, admin, csrfSvc, "email")

	h := &host{engine: eng, router: chi.NewRouter(), config: &yaml.Node{Kind: yaml.MappingNode}, logger: eng.logger}
	redirect, err := h.CompleteLogin(context.Background(), pluginapi.LoginCompletion{
		ChallengeID: "ch-3",
		CSRFToken:   csrfSvc.Token("ch-3"),
		Subject:     "user-1",
		AMR:         []string{"email_otp"},
	})
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if redirect != "http://core.example/after-login" {
		t.Fatalf("redirect = %q", redirect)
	}
	if admin.acceptLoginIn.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", admin.acceptLoginIn.Subject)
	}
	if admin.acceptLoginIn.AcceptToken != "accept-token" {
		t.Fatalf("AcceptToken = %q, want accept-token", admin.acceptLoginIn.AcceptToken)
	}
	if len(admin.acceptLoginIn.AMR) != 1 || admin.acceptLoginIn.AMR[0] != "email_otp" {
		t.Fatalf("AMR = %v", admin.acceptLoginIn.AMR)
	}
}

func TestHost_CompleteLoginRejectsBadCSRF(t *testing.T) {
	t.Parallel()

	admin := &fakeAdmin{login: &adminclient.LoginRequest{ChallengeID: "ch-3"}}
	eng := newTestEngine(t, admin, nil, "email")
	h := &host{engine: eng, router: chi.NewRouter(), logger: eng.logger}

	_, err := h.CompleteLogin(context.Background(), pluginapi.LoginCompletion{
		ChallengeID: "ch-3",
		CSRFToken:   "wrong",
		Subject:     "user-1",
	})
	if !errors.Is(err, pluginapi.ErrInvalidCSRF) {
		t.Fatalf("err = %v, want ErrInvalidCSRF", err)
	}
	if admin.adminCalls != 0 {
		t.Fatalf("admin calls = %d, want 0", admin.adminCalls)
	}
}

func TestHost_CompleteLoginRequiresSubject(t *testing.T) {
	t.Parallel()

	csrfSvc := csrf.New("test-secret")
	admin := &fakeAdmin{login: &adminclient.LoginRequest{ChallengeID: "ch-3"}}
	eng := newTestEngine(t, admin, csrfSvc, "email")
	h := &host{engine: eng, router: chi.NewRouter(), logger: eng.logger}

	_, err := h.CompleteLogin(context.Background(), pluginapi.LoginCompletion{
		ChallengeID: "ch-3",
		CSRFToken:   csrfSvc.Token("ch-3"),
	})
	if !errors.Is(err, pluginapi.ErrMissingSubject) {
		t.Fatalf("err = %v, want ErrMissingSubject", err)
	}
}
