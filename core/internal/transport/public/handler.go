package public

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/keys"
	"github.com/granto-io/granto/core/internal/oauth2"
	"github.com/granto-io/granto/core/internal/oidc"
)

// Handler is the shared HTTP adapter for public RFC endpoints.
// Protocol-specific handlers live in oauth2.go, oidc.go, and gnap.go.
type Handler struct {
	logger    *slog.Logger
	cfg       *config.Config
	flow      *oauth2.Flow
	keyMgr    *keys.Manager
	discovery *oidc.Discovery
}

// NewHandler constructs a Handler.
func NewHandler(
	logger *slog.Logger,
	cfg *config.Config,
	flow *oauth2.Flow,
	keyMgr *keys.Manager,
	discovery *oidc.Discovery,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		logger:    logger,
		cfg:       cfg,
		flow:      flow,
		keyMgr:    keyMgr,
		discovery: discovery,
	}
}

func (h *Handler) notImplemented(w http.ResponseWriter, r *http.Request, endpoint string) {
	h.logger.WarnContext(r.Context(), "public endpoint not implemented",
		"endpoint", endpoint,
		"method", r.Method,
		"path", r.URL.Path,
	)
	code := "temporarily_unavailable"
	if isGNAPPath(r.URL.Path) {
		code = "invalid_request"
	}
	writeProtocolError(w, r, http.StatusNotImplemented, code, "not implemented")
}

func (h *Handler) writeAuthorizeError(w http.ResponseWriter, err error) {
	var cre *oauth2.ClientRedirectError
	if errors.As(err, &cre) && cre.RedirectURI != "" {
		loc, e := oauth2.ClientErrorRedirectURL(
			cre.RedirectURI,
			cre.State,
			oauthErrorCode(cre.Err),
			cre.Err.Error(),
			"",
		)
		if e != nil {
			h.logger.Error("authorize client redirect", "err", e)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
			return
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
		return
	}

	switch {
	case errors.Is(err, oauth2.ErrInvalidRequest),
		errors.Is(err, oauth2.ErrUnsupportedResponseType),
		errors.Is(err, oauth2.ErrInvalidScope),
		errors.Is(err, oauth2.ErrPKCERequired),
		errors.Is(err, oauth2.ErrUnauthorizedClient),
		errors.Is(err, oauth2.ErrInvalidRedirectURI):
		writeOAuthError(w, http.StatusBadRequest, oauthErrorCode(err), err.Error())
	case errors.Is(err, oauth2.ErrInvalidClient):
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", err.Error())
	case errors.Is(err, oauth2.ErrVerifierNotFound),
		errors.Is(err, oauth2.ErrVerifierExpired):
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		h.logger.Error("authorize error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}

func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, oauth2.ErrUnsupportedResponseType):
		return "unsupported_response_type"
	case errors.Is(err, oauth2.ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, oauth2.ErrInvalidClient):
		return "invalid_client"
	case errors.Is(err, oauth2.ErrUnauthorizedClient):
		return "unauthorized_client"
	case errors.Is(err, oauth2.ErrPKCERequired):
		return "invalid_request"
	default:
		return "invalid_request"
	}
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, res *oauth2.CompleteVerifierResult) {
	if res.SessionID == uuid.Nil {
		return
	}
	c := &http.Cookie{
		Name:     oauth2.SessionCookieName,
		Value:    res.SessionID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	}
	if res.Remember {
		c.MaxAge = res.CookieMaxAgeSeconds
	}
	http.SetCookie(w, c)
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauth2.SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
}

// ensureDeviceCookie returns the browser device id, setting granto_did when missing/invalid.
func (h *Handler) ensureDeviceCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(oauth2.DeviceCookieName); err == nil {
		if id, err := uuid.Parse(strings.TrimSpace(c.Value)); err == nil && id != uuid.Nil {
			return id.String()
		}
	}
	id := uuid.New().String()
	http.SetCookie(w, &http.Cookie{
		Name:     oauth2.DeviceCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   oauth2.DeviceCookieMaxAge,
		HttpOnly: true,
		Secure:   h.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
	return id
}

func (h *Handler) cookieSecure() bool {
	return h.cfg != nil && strings.HasPrefix(h.cfg.Token.Issuer, "https://")
}
