-- Agent Mail device authorization and one-mailbox/one-Bot bindings.
--
-- Raw device codes and mailbox credentials are never stored. Requests store a
-- SHA-256 digest of the high-entropy device code; credentials use the same
-- constant-time API-key verifier as account API keys. Bot ids/profile names are
-- display metadata. Authorization evidence is the human owner's approval plus
-- proof of possession of the device-flow code verifier.

CREATE TABLE IF NOT EXISTS agent_auth_requests (
    device_hash       bytea PRIMARY KEY,
    user_code         text NOT NULL UNIQUE,
    bot_id            text NOT NULL,
    bot_profile       text NOT NULL DEFAULT '',
    client_name       text NOT NULL DEFAULT '',
    space_id          text NOT NULL DEFAULT '',
    code_challenge    text NOT NULL,
    status            text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','approved','denied','exchanged')),
    owner_principal_id bigint REFERENCES principals(id),
    account_id        bigint REFERENCES accounts(id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    approved_at       timestamptz,
    exchanged_at      timestamptz
);

-- Existing local installations may already have the table from an earlier
-- build. Schema files are replayed idempotently at startup, so add the new
-- authorization context explicitly as well as declaring it above.
ALTER TABLE agent_auth_requests
    ADD COLUMN IF NOT EXISTS space_id text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS agent_auth_requests_expiry
    ON agent_auth_requests (expires_at);

CREATE TABLE IF NOT EXISTS agent_bindings (
    id                 bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    tenant_id          bigint NOT NULL REFERENCES tenants(id),
    account_id         bigint NOT NULL REFERENCES accounts(id),
    owner_principal_id bigint NOT NULL REFERENCES principals(id),
    bot_id             text NOT NULL,
    bot_profile        text NOT NULL DEFAULT '',
    client_name        text NOT NULL DEFAULT '',
    status             text NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','revoked')),
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz,
    revoked_at         timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_bindings_one_active_per_mailbox
    ON agent_bindings (account_id) WHERE status='active';

CREATE TABLE IF NOT EXISTS agent_binding_credentials (
    id           bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    binding_id   bigint NOT NULL REFERENCES agent_bindings(id),
    key_prefix   text NOT NULL,
    cred         jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_binding_credentials_prefix
    ON agent_binding_credentials (key_prefix) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS agent_binding_credentials_binding
    ON agent_binding_credentials (binding_id);
