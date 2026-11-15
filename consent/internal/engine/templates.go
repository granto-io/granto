package engine

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

type errorPageData struct {
	Title   string
	Message string
}

type chooserPageData struct {
	ChallengeID string
	Plugins     []pluginChoice
}

type consentPageData struct {
	ChallengeID string
	CSRFToken   string
	ClientID    string
	Scopes      []string
	Remember    bool
}

func (e *Engine) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		e.logger.Error("render template", "template", name, "error", err)
	}
}

func (e *Engine) renderError(w http.ResponseWriter, status int, title, message string) {
	e.render(w, status, "error.html", errorPageData{Title: title, Message: message})
}

func (e *Engine) logAdminError(r *http.Request, action string, err error) {
	e.logger.WarnContext(r.Context(), "core admin call failed",
		"action", action,
		"method", r.Method,
		"path", r.URL.Path,
		"error", err,
	)
}
