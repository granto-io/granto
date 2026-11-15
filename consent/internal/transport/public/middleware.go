package public

import (
	"log/slog"
	"net/http"
	"time"
)

// Middleware is the stdlib-compatible plugin form:
// func(http.Handler) http.Handler.
type Middleware func(http.Handler) http.Handler

// recoverer catches panics, logs them, and returns a plain 500.
func recoverer(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.ErrorContext(r.Context(), "panic in consent HTTP handler",
						"panic", rec,
						"method", r.Method,
						"path", r.URL.Path,
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// requestLogger logs method, path, status, and latency after the handler
// runs.
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

// noCache prevents caching of login/consent pages, which carry one-shot
// challenge state in the query string. Referrer-Policy keeps that state out
// of the Referer header of any outbound link or subresource.
//
// TODO(verify): the same TODO as core's noCache applies — Referrer-Policy is a
// document policy, so the POST back to core (and any external identity
// provider redirect) will carry no Referer. Check this in the manual
// end-to-end login/consent run; if a provider or core-side check depends on
// it, scope the header to the HTML responses instead of dropping it.
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
// buffered HTML/error body — but must be fixed before adding such an endpoint
// behind requestLogger. Same limitation exists in core/internal/transport/public
// and consent/internal/transport/public; fix all of them together.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
