ALTER TABLE clients
    ADD COLUMN registration_access_token_hash VARCHAR(255),
    ADD COLUMN is_dynamic BOOLEAN NOT NULL DEFAULT false;
