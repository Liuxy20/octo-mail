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

-- The owner principal identifies who approved a Bot, but an OCTO Space is the
-- authorization boundary. Persist the approved request's Space so later
-- credential use and owner-side mutations do not infer it from a possibly
-- changed Gateway designation.
ALTER TABLE agent_bindings
    ADD COLUMN IF NOT EXISTS space_id text NOT NULL DEFAULT '';

UPDATE agent_bindings binding
SET space_id = evidence.space_id
FROM (
    SELECT DISTINCT ON (request.account_id, request.owner_principal_id, request.bot_id)
           request.account_id, request.owner_principal_id, request.bot_id,
           request.space_id
    FROM agent_auth_requests request
    WHERE request.status='exchanged' AND btrim(request.space_id) <> ''
    ORDER BY request.account_id, request.owner_principal_id, request.bot_id,
             request.exchanged_at DESC NULLS LAST, request.created_at DESC
) evidence
WHERE binding.space_id=''
  AND evidence.account_id=binding.account_id
  AND evidence.owner_principal_id=binding.owner_principal_id
  AND evidence.bot_id=binding.bot_id;

-- NOT VALID preserves startup compatibility for a legacy row whose original
-- authorization evidence is no longer available, while still rejecting every
-- new or modified binding without an explicit Space. Authentication below
-- fails closed for those unresolved legacy rows.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='agent_bindings_space_nonempty'
          AND conrelid='agent_bindings'::regclass
    ) THEN
        ALTER TABLE agent_bindings
            ADD CONSTRAINT agent_bindings_space_nonempty
            CHECK (btrim(space_id) <> '') NOT VALID;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS agent_bindings_account_space_active
    ON agent_bindings (account_id, space_id) WHERE status='active';

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
