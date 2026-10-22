-- Durable delivery buffer for audit events (stream-only).
-- Not an analytical store: rows are deleted after successful delivery to channels.
CREATE TABLE audit_outbox (
    id              BIGSERIAL PRIMARY KEY,
    payload         JSONB         NOT NULL,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now(),
    attempts        INT           NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ   NOT NULL DEFAULT now(),
    last_error      TEXT
);

CREATE INDEX idx_audit_outbox_next_attempt
    ON audit_outbox (next_attempt_at ASC, id ASC);
