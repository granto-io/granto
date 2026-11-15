package emailotp

import (
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/granto-io/granto/consent/pkg/pluginapi"
)

// Name is the registration name used in plugins.enabled.
const Name = "email-otp"

const (
	displayName  = "Email code"
	maxFormBytes = 64 << 10
)

func init() {
	pluginapi.Register(Name, func() pluginapi.Plugin { return New() })
}

// Plugin is the email one-time-code login method.
type Plugin struct {
	host     pluginapi.Host
	logger   *slog.Logger
	cfg      Config
	codes    *codeStore
	identity IdentityBackend
	mailer   Mailer

	now func() time.Time

	sendAction   string
	verifyAction string
}

// New returns a fresh plugin instance.
func New() *Plugin {
	return &Plugin{now: time.Now}
}

// Name implements pluginapi.Plugin.
func (p *Plugin) Name() string { return Name }

// DisplayName implements pluginapi.Plugin.
func (p *Plugin) DisplayName() string { return displayName }

// Kind implements pluginapi.Plugin.
func (p *Plugin) Kind() pluginapi.Kind { return pluginapi.FormKind }

// Init implements pluginapi.Plugin.
func (p *Plugin) Init(host pluginapi.Host) error {
	if host == nil {
		return errors.New("email-otp: host is required")
	}
	cfg, err := parseConfig(host.Config())
	if err != nil {
		return err
	}

	p.host = host
	p.logger = host.Logger()
	p.cfg = cfg
	if p.now == nil {
		p.now = time.Now
	}
	if p.codes == nil {
		p.codes = newCodeStore(p.now)
	}
	if p.identity == nil {
		p.identity = newIdentityBackend(host.Identity(), p.logger)
		if p.identity == nil {
			return errors.New("email-otp: identity backend is not configured")
		}
	}
	if p.mailer == nil {
		p.mailer = newLogMailer(p.logger, cfg.DevLogCodes)
	}

	prefix := "/login/" + Name
	p.sendAction = prefix + "/send"
	p.verifyAction = prefix + "/verify"

	r := host.Router()
	r.Get("/", p.handleForm)
	r.Post("/send", p.handleSend)
	r.Post("/verify", p.handleVerify)
	return nil
}

func (p *Plugin) handleForm(w http.ResponseWriter, r *http.Request) {
	challenge := strings.TrimSpace(r.URL.Query().Get("login_challenge"))
	if challenge == "" {
		p.renderError(w, http.StatusBadRequest, "The login_challenge parameter is missing.")
		return
	}

	login, err := p.host.GetLogin(r.Context(), challenge)
	if err != nil {
		p.logger.WarnContext(r.Context(), "email-otp: get login request", "error", err)
		p.renderError(w, http.StatusBadRequest, "This login request is invalid or has expired.")
		return
	}

	email := ""
	if normalized, err := normalizeEmail(login.LoginHint); err == nil {
		email = normalized
	}
	p.renderEmail(w, http.StatusOK, challenge, p.host.CSRFToken(challenge), email, "")
}

func (p *Plugin) handleSend(w http.ResponseWriter, r *http.Request) {
	if err := p.parseForm(w, r); err != nil {
		p.renderError(w, http.StatusBadRequest, "The submitted form could not be read.")
		return
	}

	challenge := strings.TrimSpace(r.PostFormValue("login_challenge"))
	csrfToken := r.PostFormValue("csrf_token")
	if err := p.host.VerifyCSRF(challenge, csrfToken); err != nil {
		p.renderError(w, http.StatusBadRequest, "The form has expired. Reload the login page and try again.")
		return
	}

	rawEmail := strings.TrimSpace(r.PostFormValue("email"))
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		p.renderEmail(w, http.StatusBadRequest, challenge, csrfToken, rawEmail, "Enter a valid email address.")
		return
	}

	// CSRF proves the browser started this challenge; GetLogin proves the
	// challenge is still pending in core before we send mail for it.
	if _, err := p.host.GetLogin(r.Context(), challenge); err != nil {
		p.logger.WarnContext(r.Context(), "email-otp: get login request", "error", err)
		p.renderError(w, http.StatusBadRequest, "This login request is invalid or has expired.")
		return
	}

	user, err := p.identity.GetOrCreateByEmail(r.Context(), email)
	if err != nil {
		p.logger.ErrorContext(r.Context(), "email-otp: resolve identity", "error", err)
		p.renderError(w, http.StatusInternalServerError, "Could not prepare the sign-in. Try again.")
		return
	}

	code, err := p.codes.issue(challenge, email, user.ID, p.cfg.CodeTTL, p.cfg.ResendCooldown)
	switch {
	case errors.Is(err, ErrCooldown):
		p.renderCode(w, http.StatusTooManyRequests, challenge, csrfToken, email,
			"A code was sent recently. Wait a minute before requesting another.", "")
		return
	case err != nil:
		p.logger.ErrorContext(r.Context(), "email-otp: issue code", "error", err)
		p.renderError(w, http.StatusInternalServerError, "Could not create a sign-in code. Try again.")
		return
	}

	if err := p.mailer.SendLoginCode(r.Context(), email, code); err != nil {
		p.codes.discard(challenge)
		p.logger.ErrorContext(r.Context(), "email-otp: send code", "error", err)
		p.renderError(w, http.StatusBadGateway, "Could not send the code. Try again.")
		return
	}

	p.renderCode(w, http.StatusOK, challenge, csrfToken, email, "", "We sent a 6-digit code to your email.")
}

func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	if err := p.parseForm(w, r); err != nil {
		p.renderError(w, http.StatusBadRequest, "The submitted form could not be read.")
		return
	}

	challenge := strings.TrimSpace(r.PostFormValue("login_challenge"))
	csrfToken := r.PostFormValue("csrf_token")
	if err := p.host.VerifyCSRF(challenge, csrfToken); err != nil {
		p.renderError(w, http.StatusBadRequest, "The form has expired. Reload the login page and try again.")
		return
	}

	email, err := normalizeEmail(r.PostFormValue("email"))
	if err != nil {
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, "", "Enter the email you used to request the code.", "")
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	if len(code) != 6 {
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, email, "Enter the 6-digit code from the email.", "")
		return
	}

	if _, err := p.host.GetLogin(r.Context(), challenge); err != nil {
		p.logger.WarnContext(r.Context(), "email-otp: get login request", "error", err)
		p.renderError(w, http.StatusBadRequest, "This login request is invalid or has expired.")
		return
	}

	subject, err := p.codes.verify(challenge, email, code, p.cfg.MaxAttempts)
	switch {
	case errors.Is(err, ErrCodeMismatch):
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, email, "Incorrect code. Try again.", "")
		return
	case errors.Is(err, ErrTooManyAttempts):
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, email, "Too many attempts. Request a new code.", "")
		return
	case errors.Is(err, ErrCodeExpired):
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, email, "The code has expired. Request a new one.", "")
		return
	case errors.Is(err, ErrCodeNotFound):
		p.renderCode(w, http.StatusBadRequest, challenge, csrfToken, email, "Request a code first.", "")
		return
	case err != nil:
		p.logger.ErrorContext(r.Context(), "email-otp: verify code", "error", err)
		p.renderError(w, http.StatusInternalServerError, "Could not verify the code. Try again.")
		return
	}

	redirect, err := p.host.CompleteLogin(r.Context(), pluginapi.LoginCompletion{
		ChallengeID: challenge,
		CSRFToken:   csrfToken,
		Subject:     subject,
		AMR:         []string{"email_otp"},
	})
	if err != nil {
		p.logger.WarnContext(r.Context(), "email-otp: complete login", "error", err)
		p.renderError(w, http.StatusBadRequest, "This login request is invalid or has expired.")
		return
	}

	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (p *Plugin) parseForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	return r.ParseForm()
}

func normalizeEmail(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 {
		return "", errors.New("email-otp: invalid email")
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return "", errors.New("email-otp: invalid email")
	}
	return strings.ToLower(addr.Address), nil
}

func (p *Plugin) renderEmail(w http.ResponseWriter, status int, challenge, csrfToken, email, errMsg string) {
	p.render(w, status, "email.html", emailPageData{
		Action:      p.sendAction,
		ChallengeID: challenge,
		CSRFToken:   csrfToken,
		Email:       email,
		Error:       errMsg,
		DevLogCodes: p.cfg.DevLogCodes,
	})
}

func (p *Plugin) renderCode(w http.ResponseWriter, status int, challenge, csrfToken, email, errMsg, notice string) {
	p.render(w, status, "code.html", codePageData{
		VerifyAction: p.verifyAction,
		ResendAction: p.sendAction,
		ChallengeID:  challenge,
		CSRFToken:    csrfToken,
		Email:        email,
		Error:        errMsg,
		Notice:       notice,
		DevLogCodes:  p.cfg.DevLogCodes,
	})
}

func (p *Plugin) renderError(w http.ResponseWriter, status int, message string) {
	p.render(w, status, "error.html", errorPageData{Message: message})
}

func (p *Plugin) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pluginTemplates.ExecuteTemplate(w, name, data); err != nil {
		p.logger.Error("email-otp: render template", "template", name, "error", err)
	}
}
