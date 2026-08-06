package migrations

import "embed"

// FS holds SQL migration files for golang-migrate (iofs source).
//
//go:embed *.sql
var FS embed.FS
