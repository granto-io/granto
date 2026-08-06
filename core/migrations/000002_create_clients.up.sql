CREATE TABLE clients (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants (id),

    client_id         VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(255),
    name              VARCHAR(255) NOT NULL,
    description       TEXT,

    client_type       VARCHAR(20) NOT NULL
                      CHECK (client_type IN ('confidential', 'public', 'trusted')),

    grant_types          TEXT[] NOT NULL DEFAULT '{}',
    response_types       TEXT[] NOT NULL DEFAULT '{}',
    redirect_uris        TEXT[] NOT NULL DEFAULT '{}',
    allowed_cors_origins TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes       TEXT[] NOT NULL DEFAULT '{}',
    default_scopes       TEXT[] NOT NULL DEFAULT '{}',
    audience             TEXT[] NOT NULL DEFAULT '{}',

    token_endpoint_auth_method      VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_endpoint_auth_method IN (
            'client_secret_basic',
            'client_secret_post',
            'client_secret_jwt',
            'private_key_jwt',
            'none'
        )),
    token_endpoint_auth_signing_alg VARCHAR(20),
    require_pkce                    BOOLEAN NOT NULL DEFAULT false,

    subject_type          VARCHAR(20) NOT NULL DEFAULT 'public'
                          CHECK (subject_type IN ('public', 'pairwise')),
    sector_identifier_uri TEXT,
    id_token_signed_alg   VARCHAR(20) NOT NULL DEFAULT 'RS256',
    userinfo_signed_alg   VARCHAR(20) NOT NULL DEFAULT 'none',

    post_logout_uris                      TEXT[] NOT NULL DEFAULT '{}',
    frontchannel_logout_uri               TEXT,
    frontchannel_logout_session_required  BOOLEAN NOT NULL DEFAULT false,
    backchannel_logout_uri                TEXT,
    backchannel_logout_session_required   BOOLEAN NOT NULL DEFAULT false,

    access_token_ttl  INTERVAL,
    refresh_token_ttl INTERVAL,
    id_token_ttl      INTERVAL,

    skip_consent BOOLEAN NOT NULL DEFAULT false,

    logo_uri   TEXT,
    client_uri TEXT,
    policy_uri TEXT,
    tos_uri    TEXT,
    contacts   TEXT[],
    metadata   JSONB NOT NULL DEFAULT '{}',

    protocols TEXT[] NOT NULL DEFAULT '{oauth2,oidc}',
    jwks      JSONB,
    jwks_uri  TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    UNIQUE (tenant_id, client_id)
);

CREATE INDEX idx_clients_tenant_client
    ON clients (tenant_id, client_id)
    WHERE deleted_at IS NULL;
