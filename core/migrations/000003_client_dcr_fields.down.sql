ALTER TABLE clients
    DROP COLUMN IF EXISTS registration_access_token_hash,
    DROP COLUMN IF EXISTS is_dynamic;
