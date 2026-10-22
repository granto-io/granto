ALTER TABLE login_sessions
    ADD COLUMN device_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_login_sessions_tenant_device
    ON login_sessions (tenant_id, device_id)
    WHERE device_id <> '';
