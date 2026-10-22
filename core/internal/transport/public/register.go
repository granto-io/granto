package public

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/granto-io/granto/core/internal/oauth2"
)

const maxRegisterBody = 1 << 20 // 1 MiB

// OIDC Dynamic Client Registration (RFC 7591) — public surface when
// oidc.dynamic_client_registration.enabled is true.

func (h *Handler) handleRegisterCreate(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "dynamic-client-registration")
		return
	}
	in, err := decodeDynamicClientRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	out, err := h.flow.RegisterDynamicClient(r.Context(), in)
	if err != nil {
		h.writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handler) handleRegisterRead(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "dynamic-client-registration-read")
		return
	}
	out, err := h.flow.GetDynamicClient(r.Context(), chi.URLParam(r, "clientID"), bearerToken(r))
	if err != nil {
		h.writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleRegisterUpdate(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "dynamic-client-registration-update")
		return
	}
	in, err := decodeDynamicClientRequest(r)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	out, err := h.flow.UpdateDynamicClient(r.Context(), chi.URLParam(r, "clientID"), bearerToken(r), in)
	if err != nil {
		h.writeRegisterError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleRegisterDelete(w http.ResponseWriter, r *http.Request) {
	if h.flow == nil {
		h.notImplemented(w, r, "dynamic-client-registration-delete")
		return
	}
	if err := h.flow.DeleteDynamicClient(r.Context(), chi.URLParam(r, "clientID"), bearerToken(r)); err != nil {
		h.writeRegisterError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeDynamicClientRequest(r *http.Request) (oauth2.DynamicClientRequest, error) {
	var in oauth2.DynamicClientRequest
	defer r.Body.Close() //nolint:errcheck
	// RFC 7591: AS must ignore unrecognized metadata parameters.
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRegisterBody))
	if err := dec.Decode(&in); err != nil {
		return in, err
	}
	return in, nil
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

func (h *Handler) writeRegisterError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, oauth2.ErrInvalidRequest):
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
	case errors.Is(err, oauth2.ErrInvalidToken):
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "invalid registration_access_token")
	default:
		h.logger.Error("dynamic client registration error", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
	}
}
