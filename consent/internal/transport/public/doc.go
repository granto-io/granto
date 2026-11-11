// Package public implements the consent service's own HTTP surface: the
// login and consent pages shown to end users.
//
// This package is the HTTP adapter layer only; orchestration belongs to the
// engine (added in a later step). The process-level health probe is
// registered separately by pkg/server, not here (see core/internal/app for
// the same split).
package public
