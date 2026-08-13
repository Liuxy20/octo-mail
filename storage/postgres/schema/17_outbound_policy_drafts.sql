-- Durable business-policy metadata for Agent-originated messages held in Drafts.
-- Message content remains in the normal account message/blob model. This table
-- stores only the review workflow projection and is always account-scoped.

CREATE TABLE IF NOT EXISTS outbound_policy_drafts (
    account_id       bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email_id         bigint NOT NULL,
    status           text NOT NULL CHECK (status IN ('pending_confirmation','system_blocked')),
    draft_version    integer NOT NULL DEFAULT 1 CHECK (draft_version > 0),
    policy_version   text NOT NULL,
    reasons          jsonb NOT NULL DEFAULT '[]'::jsonb,
    source           text NOT NULL CHECK (source IN ('owner_direct','inbound_auto_reply')),
    source_email_id  bigint,
    content_digest   bytea NOT NULL,
    idempotency_key  text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, email_id),
    UNIQUE (account_id, idempotency_key),
    CHECK (length(policy_version) BETWEEN 1 AND 200),
    CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    CHECK (octet_length(content_digest) = 32)
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS outbound_policy_drafts_p0 PARTITION OF outbound_policy_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS outbound_policy_drafts_p1 PARTITION OF outbound_policy_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS outbound_policy_drafts_p2 PARTITION OF outbound_policy_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS outbound_policy_drafts_p3 PARTITION OF outbound_policy_drafts FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS outbound_policy_drafts_status_recent
    ON outbound_policy_drafts (account_id, status, updated_at DESC, email_id DESC);
