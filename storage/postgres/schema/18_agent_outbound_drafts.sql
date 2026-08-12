-- Workflow metadata for Agent-prepared messages held in the normal Drafts
-- mailbox. The RFC message/blob remains the source of message content.

CREATE TABLE IF NOT EXISTS agent_outbound_drafts (
    account_id       bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email_id         bigint NOT NULL,
    draft_type       text NOT NULL CHECK (draft_type IN ('agent_pending_confirmation','agent_reply_draft')),
    status           text NOT NULL CHECK (status IN ('pending_confirmation','system_blocked')),
    draft_version    integer NOT NULL DEFAULT 1 CHECK (draft_version > 0),
    source_email_id  bigint,
    content_digest   bytea NOT NULL,
    idempotency_key  text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, email_id),
    UNIQUE (account_id, idempotency_key),
    CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    CHECK (octet_length(content_digest) = 32)
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS agent_outbound_drafts_p0 PARTITION OF agent_outbound_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS agent_outbound_drafts_p1 PARTITION OF agent_outbound_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS agent_outbound_drafts_p2 PARTITION OF agent_outbound_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS agent_outbound_drafts_p3 PARTITION OF agent_outbound_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS agent_outbound_drafts_status_recent
    ON agent_outbound_drafts (account_id, status, updated_at DESC, email_id DESC);
