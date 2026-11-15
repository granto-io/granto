package engine

import (
	"net/http"
	"strings"

	"github.com/granto-io/granto/consent/internal/adminclient"
)

const maxFormBytes = 64 << 10

func (e *Engine) handleConsentGet(w http.ResponseWriter, r *http.Request) {
	challenge := strings.TrimSpace(r.URL.Query().Get("consent_challenge"))
	if challenge == "" {
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"The consent_challenge parameter is missing.")
		return
	}

	req, err := e.admin.GetConsent(r.Context(), challenge)
	if err != nil {
		e.logAdminError(r, "get consent request", err)
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"This consent request is invalid or has expired.")
		return
	}

	e.render(w, http.StatusOK, "consent.html", consentPageData{
		ChallengeID: challenge,
		CSRFToken:   e.csrf.Token(challenge),
		ClientID:    req.ClientID,
		Scopes:      req.RequestedScope,
		Remember:    false,
	})
}

func (e *Engine) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"The submitted form could not be read.")
		return
	}

	challenge := strings.TrimSpace(r.PostFormValue("consent_challenge"))
	if err := e.csrf.Verify(challenge, r.PostFormValue("csrf_token")); err != nil {
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"The form has expired. Reload the consent page and try again.")
		return
	}

	req, err := e.admin.GetConsent(r.Context(), challenge)
	if err != nil {
		e.logAdminError(r, "get consent request", err)
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"This consent request is invalid or has expired.")
		return
	}

	var redirect string
	switch r.PostFormValue("decision") {
	case "accept":
		redirect, err = e.admin.AcceptConsent(r.Context(), adminclient.AcceptConsentInput{
			ChallengeID:   challenge,
			GrantScope:    req.RequestedScope,
			GrantScopeSet: true,
			Remember:      r.PostFormValue("remember") != "",
			AcceptToken:   req.AcceptToken,
		})
		if err != nil {
			e.logAdminError(r, "accept consent request", err)
		}
	case "reject":
		redirect, err = e.admin.RejectConsent(r.Context(), adminclient.RejectInput{
			ChallengeID:      challenge,
			Error:            "access_denied",
			ErrorDescription: "the resource owner denied the request",
			AcceptToken:      req.AcceptToken,
		})
		if err != nil {
			e.logAdminError(r, "reject consent request", err)
		}
	default:
		e.renderError(w, http.StatusBadRequest, "Invalid consent request",
			"Unknown consent decision.")
		return
	}
	if err != nil {
		e.renderError(w, http.StatusBadRequest, "Consent failed",
			"This consent request is invalid or has expired.")
		return
	}
	if redirect == "" {
		e.renderError(w, http.StatusBadGateway, "Consent failed",
			"Core did not return a redirect target.")
		return
	}

	http.Redirect(w, r, redirect, http.StatusSeeOther)
}
