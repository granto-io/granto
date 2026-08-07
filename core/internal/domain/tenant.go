package domain

import "github.com/google/uuid"

// DefaultTenantID is the MVP single-tenant row seeded by migrations
// (slug "default").
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
