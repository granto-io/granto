// Package public implements the public-facing OAuth2 / OIDC / GNAP HTTP transport.
//
// This package is the HTTP adapter layer only. Business logic belongs in
// domain services (oauth2, oidc, gnap, …), not here.
//
// OpenTelemetry HTTP instrumentation (otelhttp) is applied by the application
// when constructing http.Server, so the same TracerProvider can wrap both
// this router and the grpc-gateway mux.
//
// Error bodies: OAuth/OIDC use writeOAuthError (RFC 6749); GNAP uses
// writeGNAPError (RFC 9635 §3.6). Path prefix /gnap selects the shape.
package public
