CREATE TABLE consent_grants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants (id),

    subject   TEXT NOT NULL,
    client_id TEXT NOT NULL,

    scopes   TEXT[] NOT NULL DEFAULT '{}',
    audience TEXT[] NOT NULL DEFAULT '{}',

    -- NULL = no expiry (until revoked / overwritten).
    expires_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, subject, client_id)
);

CREATE INDEX idx_consent_grants_expires_at
    ON consent_grants (expires_at)
    WHERE expires_at IS NOT NULL;
