package public

import (
	"encoding/json"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeOAuthError writes a minimal RFC 6749-style error body.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// gnapErrorObject is the object form of RFC 9635 §3.6.
type gnapErrorObject struct {
	Code        string `json:"code"`
	Description string `json:"description,omitempty"`
}

// writeGNAPError writes an RFC 9635 §3.6 error using the object form
// (code + optional description). Prefer this over the string-only form
// so clients always get a machine-readable code field path.
func writeGNAPError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]any{
		"error": gnapErrorObject{
			Code:        code,
			Description: description,
		},
	})
}

// writeProtocolError picks OAuth vs GNAP error shape from the request path.
func writeProtocolError(w http.ResponseWriter, r *http.Request, status int, code, description string) {
	if strings.HasPrefix(r.URL.Path, "/gnap") {
		writeGNAPError(w, status, code, description)
		return
	}
	writeOAuthError(w, status, code, description)
}
