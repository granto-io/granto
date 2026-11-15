// Package public implements the consent service's own HTTP surface: the
// login and consent pages shown to end users.
//
// This package is the HTTP adapter layer: middleware, routing, and the
// process-level split of health from the protocol surface. Orchestration
// (challenges, plugins, CSRF) lives in internal/engine. The process health
// probe is registered separately by pkg/server.
package public
