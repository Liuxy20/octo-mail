-- Durable idempotency projection for proactive automatic Agent sends.
-- A row is claimed before any Sent/queue side effect. A stale processing row
-- intentionally blocks replay because the previous result may be unknown.

CREATE TABLE IF NOT EXISTS agent_send_intents (
    account_id       bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    idempotency_key  text NOT NULL,
    content_digest   bytea NOT NULL,
    status           text NOT NULL DEFAULT 'processing'
                     CHECK (status IN ('processing','accepted')),
    message_id       bigint,
    submission_ids   bigint[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, idempotency_key),
    CHECK (length(idempotency_key) BETWEEN 8 AND 200),
    CHECK (octet_length(content_digest) = 32),
    CHECK (
      (status='processing' AND message_id IS NULL) OR
      (status='accepted' AND message_id IS NOT NULL)
    )
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS agent_send_intents_p0 PARTITION OF agent_send_intents FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS agent_send_intents_p1 PARTITION OF agent_send_intents FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS agent_send_intents_p2 PARTITION OF agent_send_intents FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS agent_send_intents_p3 PARTITION OF agent_send_intents FOR VALUES WITH (MODULUS 4, REMAINDER 3);
