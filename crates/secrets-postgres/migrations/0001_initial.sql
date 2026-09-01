CREATE TABLE secrets (
    id uuid PRIMARY KEY,
    tenant text NOT NULL,
    namespace text NOT NULL,
    secret_key text NOT NULL,
    owner_subject text NOT NULL,
    disclosure text NOT NULL CHECK (disclosure IN ('workload_only', 'user_revealable')),
    state text NOT NULL CHECK (state IN ('active', 'revoked')),
    current_version bigint NOT NULL CHECK (current_version > 0),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant, namespace, secret_key)
);

CREATE TABLE secret_versions (
    secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version bigint NOT NULL,
    ciphertext bytea NOT NULL,
    value_nonce bytea NOT NULL CHECK (octet_length(value_nonce) = 12),
    wrapped_key bytea NOT NULL,
    wrap_nonce bytea NOT NULL CHECK (octet_length(wrap_nonce) = 12),
    key_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (secret_id, version)
);

CREATE TABLE prepared_transactions (
    id uuid NOT NULL,
    tenant text NOT NULL,
    actor text NOT NULL,
    mutations jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);

CREATE TABLE audit_events (
    sequence bigserial PRIMARY KEY,
    tenant text NOT NULL,
    secret_id uuid,
    actor text NOT NULL,
    action text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX secrets_tenant_owner_idx ON secrets(tenant, owner_subject, updated_at DESC);
CREATE INDEX audit_events_tenant_idx ON audit_events(tenant, sequence DESC);

