package public

import (
	"log/slog"
	"net/http"
	"time"
)

// recoverer catches panics, logs them, and returns a protocol-shaped error.
func recoverer(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.ErrorContext(r.Context(), "panic in public HTTP handler",
						"panic", rec,
						"method", r.Method,
						"path", r.URL.Path,
					)
					// OAuth: server_error; GNAP: request_denied (no dedicated 5xx code in registry).
					code := "server_error"
					if isGNAPPath(r.URL.Path) {
						code = "request_denied"
					}
					writeProtocolError(w, r, http.StatusInternalServerError, code, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogger logs method, path, status, and latency after the handler runs.
func requestLogger(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			logger.InfoContext(r.Context(), "http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"latency_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// noCache sets Cache-Control / Pragma required for OAuth token responses
// (RFC 6749 §5.1). Applied broadly on the public surface for simplicity;
// tighten per-route later if needed. Referrer-Policy keeps request parameters
// (client_id, state, challenge ids) out of the Referer header of any outbound
// link or subresource.
//
// TODO(verify): Referrer-Policy is a *document* policy — it also changes the
// Referer the browser sends on requests that originate from our responses,
// including 30x hops. This middleware covers the whole public surface, not
// just error bodies, so things that could break in the OAuth2/OIDC flow and
// must be re-checked in the manual end-to-end run once the flow is assembled:
//   - /oauth2/auth → login/consent redirect: the login page request, and then
//     the redirect back to the client, may arrive without a Referer. A
//     third-party consent UI or RP that validates Referer against its own
//     origin, or builds a "return to app" link from it, would see it empty.
//   - RP-side JS reading document.referrer after the callback (analytics,
//     back-navigation) gets an empty value.
//   - RPs doing legacy Referer-based CSRF checks on their own endpoints see no
//     Referer when the navigation started here.
//   - HTML error pages served from this surface lose the referrer of their
//     outbound links.
//
// Non-browser clients are unaffected (they never send Referer). If any of the
// above turns out to matter, scope the header to the HTML/error paths instead
// of the whole public router — do not just drop it, since it shields the
// challenge ids that travel in the authorize query string.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// TODO(tech-debt): statusRecorder wraps http.ResponseWriter but does not
// forward http.Flusher (Flush), http.Hijacker, or http.ResponseController's
// Unwrap, so any handler that needs to flush (SSE, chunked streaming) or
// hijack the connection (WebSocket, Upgrade) through this middleware would
// silently lose that capability. Harmless today — every response here is a
// buffered JSON/error body — but must be fixed before adding such an endpoint
// behind requestLogger. Same limitation exists in consent/internal/transport/public;
// fix all of them together.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
