// Package redis will hold Redis-backed repositories (sessions, auth codes, …).
//
// The shared base (client + optional MULTI/EXEC helpers) lands with the first
// concrete Redis repository — semantics differ from SQL transactions.
package redis
