DROP INDEX IF EXISTS idx_login_sessions_tenant_device;

ALTER TABLE login_sessions
    DROP COLUMN IF EXISTS device_id;
