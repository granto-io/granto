package engine

import (
	"net/http"
	"net/url"
	"strings"
)

// handleLogin resolves the login challenge to an enabled plugin. With one
// plugin the browser goes straight to its form; with several a chooser is
// rendered. The plugin validates the challenge itself.
func (e *Engine) handleLogin(w http.ResponseWriter, r *http.Request) {
	challenge := strings.TrimSpace(r.URL.Query().Get("login_challenge"))
	if challenge == "" {
		e.renderError(w, http.StatusBadRequest, "Invalid login request",
			"The login_challenge parameter is missing.")
		return
	}

	if len(e.choices) == 1 {
		target := "/login/" + url.PathEscape(e.choices[0].Name) + "?login_challenge=" + url.QueryEscape(challenge)
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	e.render(w, http.StatusOK, "chooser.html", chooserPageData{
		ChallengeID: challenge,
		Plugins:     e.choices,
	})
}
