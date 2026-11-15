package emailotp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"

	"github.com/granto-io/granto/consent/internal/csrf"
	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeHost struct {
	router   chi.Router
	cfg      *yaml.Node
	csrf     *csrf.Service
	login    *pluginapi.LoginRequest
	loginErr error

	completeIn       pluginapi.LoginCompletion
	completeRedirect string
	completeErr      error
}

func (h *fakeHost) Logger() *slog.Logger { return testLogger }
func (h *fakeHost) Config() *yaml.Node   { return h.cfg }
func (h *fakeHost) Router() chi.Router   { return h.router }
func (h *fakeHost) CSRFToken(challenge string) string {
	return h.csrf.Token(challenge)
}
func (h *fakeHost) VerifyCSRF(challenge, token string) error {
	if err := h.csrf.Verify(challenge, token); err != nil {
		return errors.Join(pluginapi.ErrInvalidCSRF, err)
	}
	return nil
}
func (h *fakeHost) GetLogin(_ context.Context, challenge string) (*pluginapi.LoginRequest, error) {
	if h.loginErr != nil {
		return nil, h.loginErr
	}
	if h.login != nil {
		return h.login, nil
	}
	return &pluginapi.LoginRequest{ChallengeID: challenge}, nil
}
func (h *fakeHost) Identity() pluginapi.IdentityClient { return nil }
func (h *fakeHost) CompleteLogin(_ context.Context, in pluginapi.LoginCompletion) (string, error) {
	if err := h.VerifyCSRF(in.ChallengeID, in.CSRFToken); err != nil {
		return "", err
	}
	h.completeIn = in
	if h.completeErr != nil {
		return "", h.completeErr
	}
	return h.completeRedirect, nil
}
func (h *fakeHost) RejectLogin(_ context.Context, in pluginapi.LoginRejection) (string, error) {
	return "", errors.New("not implemented in tests")
}

type fakeMailer struct {
	calls    int
	lastTo   string
	lastCode string
	err      error
}

func (m *fakeMailer) SendLoginCode(_ context.Context, to, code string) error {
	m.calls++
	m.lastTo = to
	m.lastCode = code
	return m.err
}

type fixedIdentity struct {
	id string
}

func (f fixedIdentity) GetOrCreateByEmail(_ context.Context, _ string) (*User, error) {
	return &User{ID: f.id, Email: "user@example.com"}, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type testEnv struct {
	plugin *Plugin
	host   *fakeHost
	mailer *fakeMailer
	clock  *clock
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	cfgNode := &yaml.Node{}
	if err := cfgNode.Encode(map[string]any{"dev_log_codes": false}); err != nil {
		t.Fatalf("encode config: %v", err)
	}

	clk := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	host := &fakeHost{
		router: chi.NewRouter(),
		cfg:    cfgNode,
		csrf:   csrf.New("test-secret"),
		login:  &pluginapi.LoginRequest{ChallengeID: "ch-1", LoginHint: "hint@example.com"},
	}
	p := New()
	p.now = clk.now
	p.identity = fixedIdentity{id: "user-1"}
	mailer := &fakeMailer{}
	p.mailer = mailer

	if err := p.Init(host); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return &testEnv{plugin: p, host: host, mailer: mailer, clock: clk}
}

func (e *testEnv) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rr := httptest.NewRecorder()
	e.host.router.ServeHTTP(rr, req)
	return rr
}

func (e *testEnv) sendForm(email string) url.Values {
	return url.Values{
		"login_challenge": {"ch-1"},
		"csrf_token":      {e.host.csrf.Token("ch-1")},
		"email":           {email},
	}
}

func (e *testEnv) verifyForm(code string) url.Values {
	return url.Values{
		"login_challenge": {"ch-1"},
		"csrf_token":      {e.host.csrf.Token("ch-1")},
		"email":           {"user@example.com"},
		"code":            {code},
	}
}

func TestForm_PrefillsLoginHint(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	rr := env.do(http.MethodGet, "/?login_challenge=ch-1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "hint@example.com") {
		t.Fatal("form does not prefill the login hint")
	}
}

func TestForm_MissingChallenge(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	rr := env.do(http.MethodGet, "/", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}

func TestSend_IssuesCode(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	rr := env.do(http.MethodPost, "/send", env.sendForm("User@Example.com"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if env.mailer.calls != 1 {
		t.Fatalf("mailer calls = %d, want 1", env.mailer.calls)
	}
	if env.mailer.lastTo != "user@example.com" {
		t.Fatalf("mailer to = %q, want normalized address", env.mailer.lastTo)
	}
	if len(env.mailer.lastCode) != 6 {
		t.Fatalf("code = %q, want 6 digits", env.mailer.lastCode)
	}
	if !strings.Contains(rr.Body.String(), `name="code"`) {
		t.Fatal("response does not render the code form")
	}
}

func TestSend_RejectsInvalidEmail(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	rr := env.do(http.MethodPost, "/send", env.sendForm("not-an-email"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if env.mailer.calls != 0 {
		t.Fatalf("mailer calls = %d, want 0", env.mailer.calls)
	}
}

func TestSend_RejectsBadCSRF(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	form := env.sendForm("user@example.com")
	form.Set("csrf_token", "wrong")
	rr := env.do(http.MethodPost, "/send", form)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if env.mailer.calls != 0 {
		t.Fatalf("mailer calls = %d, want 0", env.mailer.calls)
	}
}

func TestSend_Cooldown(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("first send status=%d, want 200", rr.Code)
	}
	rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com"))
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second send status=%d, want 429", rr.Code)
	}
	if env.mailer.calls != 1 {
		t.Fatalf("mailer calls = %d, want 1", env.mailer.calls)
	}
}

func TestVerify_Success(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	env.host.completeRedirect = "http://core.example/after-login"

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("send status=%d, want 200", rr.Code)
	}

	rr := env.do(http.MethodPost, "/verify", env.verifyForm(env.mailer.lastCode))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303; body=%s", rr.Code, rr.Body.String())
	}
	if got, want := rr.Header().Get("Location"), "http://core.example/after-login"; got != want {
		t.Fatalf("Location=%q, want %q", got, want)
	}
	if env.host.completeIn.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", env.host.completeIn.Subject)
	}
	if len(env.host.completeIn.AMR) != 1 || env.host.completeIn.AMR[0] != "email_otp" {
		t.Fatalf("AMR = %v, want [email_otp]", env.host.completeIn.AMR)
	}
}

func TestVerify_EmailMismatchDoesNotConsumeAttempt(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("send status=%d, want 200", rr.Code)
	}

	// A tampered email must be rejected without burning an attempt budget.
	form := env.verifyForm(env.mailer.lastCode)
	form.Set("email", "attacker@example.com")
	rr := env.do(http.MethodPost, "/verify", form)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}

	// The correct email + code still works afterwards.
	rr = env.do(http.MethodPost, "/verify", env.verifyForm(env.mailer.lastCode))
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status=%d, want 303; body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerify_WrongCode(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("send status=%d, want 200", rr.Code)
	}
	rr := env.do(http.MethodPost, "/verify", env.verifyForm("000000"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Incorrect code") {
		t.Fatal("expected an incorrect-code message")
	}
}

func TestVerify_Expired(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("send status=%d, want 200", rr.Code)
	}
	env.clock.t = env.clock.t.Add(11 * time.Minute)

	rr := env.do(http.MethodPost, "/verify", env.verifyForm(env.mailer.lastCode))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "expired") {
		t.Fatal("expected an expired-code message")
	}
}

func TestVerify_TooManyAttempts(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	if rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com")); rr.Code != http.StatusOK {
		t.Fatalf("send status=%d, want 200", rr.Code)
	}

	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = env.do(http.MethodPost, "/verify", env.verifyForm("000000"))
	}
	if last.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", last.Code)
	}
	if !strings.Contains(last.Body.String(), "Too many attempts") {
		t.Fatal("expected a too-many-attempts message")
	}

	// The attempt budget is gone even for the right code.
	rr := env.do(http.MethodPost, "/verify", env.verifyForm(env.mailer.lastCode))
	if !strings.Contains(rr.Body.String(), "Request a code first") && !strings.Contains(rr.Body.String(), "Too many attempts") {
		t.Fatalf("body = %s, want a rejected-code message", rr.Body.String())
	}
}

func TestVerify_RequiresSixDigits(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)

	rr := env.do(http.MethodPost, "/verify", env.verifyForm("123"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "6-digit code") {
		t.Fatal("expected a 6-digit code message")
	}
}

func TestSend_MailerFailureDiscardsCode(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	env.mailer.err = errors.New("smtp down")

	rr := env.do(http.MethodPost, "/send", env.sendForm("user@example.com"))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", rr.Code)
	}
	if _, err := env.plugin.codes.verify("ch-1", "user@example.com", "000000", 5); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("verify after discard = %v, want ErrCodeNotFound", err)
	}
}

func TestForm_GetLoginFailure(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	env.host.loginErr = errors.New("challenge not found")

	rr := env.do(http.MethodGet, "/?login_challenge=ch-1", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}
