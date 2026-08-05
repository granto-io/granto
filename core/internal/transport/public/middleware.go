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
// tighten per-route later if needed.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *statusRecorder) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
