package public

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/granto-io/granto/core/internal/config"
	"github.com/granto-io/granto/core/internal/oauth2"
)

// Handler is the shared HTTP adapter for public RFC endpoints.
// Protocol-specific handlers live in oauth2.go, oidc.go, and gnap.go.
type Handler struct {
	logger *slog.Logger
	cfg    *config.Config
	flow   *oauth2.Flow
}

// NewHandler constructs a Handler.
func NewHandler(logger *slog.Logger, cfg *config.Config, flow *oauth2.Flow) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{logger: logger, cfg: cfg, flow: flow}
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
	switch {
	case errors.Is(err, oauth2.ErrInvalidRequest),
		errors.Is(err, oauth2.ErrUnsupportedResponseType),
		errors.Is(err, oauth2.ErrInvalidScope),
		errors.Is(err, oauth2.ErrPKCERequired),
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
		Secure:   strings.HasPrefix(h.cfg.Token.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
	}
	if res.Remember {
		c.MaxAge = res.CookieMaxAgeSeconds
	}
	http.SetCookie(w, c)
}
