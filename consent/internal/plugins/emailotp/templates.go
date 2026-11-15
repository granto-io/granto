package emailotp

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templateFS embed.FS

var pluginTemplates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

type emailPageData struct {
	Action      string
	ChallengeID string
	CSRFToken   string
	Email       string
	Error       string
	DevLogCodes bool
}

type codePageData struct {
	VerifyAction string
	ResendAction string
	ChallengeID  string
	CSRFToken    string
	Email        string
	Error        string
	Notice       string
	DevLogCodes  bool
}

type errorPageData struct {
	Message string
}
