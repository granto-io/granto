CREATE TABLE login_sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants (id),

    subject          TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    remember         BOOLEAN NOT NULL DEFAULT false,

    acr                        TEXT NOT NULL DEFAULT '',
    amr                        TEXT[] NOT NULL DEFAULT '{}',
    identity_provider_session_id TEXT,
    metadata                   JSONB NOT NULL DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_sessions_tenant_subject
    ON login_sessions (tenant_id, subject);

CREATE INDEX idx_login_sessions_expires_at
    ON login_sessions (expires_at);
