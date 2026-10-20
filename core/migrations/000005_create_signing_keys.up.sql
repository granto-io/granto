CREATE TABLE signing_keys (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID         NOT NULL REFERENCES tenants (id),

    kid         VARCHAR(255) NOT NULL,
    algorithm   VARCHAR(20)  NOT NULL,
    use         VARCHAR(10)  NOT NULL CHECK (use IN ('sig', 'enc')),

    public_key  TEXT         NOT NULL,
    private_key TEXT         NOT NULL,

    is_active   BOOLEAN      NOT NULL DEFAULT true,
    rotated_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,

    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, kid)
);

CREATE INDEX idx_signing_keys_active
    ON signing_keys (tenant_id, algorithm, is_active)
    WHERE is_active = true;

-- At most one active signing key per (tenant, algorithm) for safe concurrent ensure.
CREATE UNIQUE INDEX idx_one_active_key_per_algo
    ON signing_keys (tenant_id, algorithm)
    WHERE is_active = true;
