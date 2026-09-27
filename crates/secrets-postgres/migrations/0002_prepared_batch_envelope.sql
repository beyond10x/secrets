DELETE FROM prepared_transactions;

ALTER TABLE prepared_transactions
    DROP COLUMN mutations,
    ADD COLUMN ciphertext bytea NOT NULL,
    ADD COLUMN value_nonce bytea NOT NULL CHECK (octet_length(value_nonce) = 12),
    ADD COLUMN wrapped_key bytea NOT NULL,
    ADD COLUMN wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
    ADD COLUMN key_id text NOT NULL,
    ADD COLUMN expires_at timestamptz NOT NULL;

CREATE INDEX prepared_transactions_tenant_expiry_idx ON prepared_transactions(tenant, expires_at);
