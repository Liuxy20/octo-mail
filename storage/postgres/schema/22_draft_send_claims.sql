-- Durable multi-node claims for sending one immutable Draft exactly once.
-- The Draft message may be removed after acceptance, so email_id deliberately
-- has no foreign key to messages. Successful claims are deleted after Draft
-- cleanup; a retained processing row means the result may be unknown.

CREATE TABLE IF NOT EXISTS draft_send_claims (
    account_id       bigint NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email_id         bigint NOT NULL,
    draft_version    integer NOT NULL CHECK (draft_version >= 0),
    content_digest   bytea NOT NULL,
    status           text NOT NULL DEFAULT 'processing'
                     CHECK (status IN ('processing','accepted')),
    message_id       bigint,
    submission_ids   bigint[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, email_id),
    CHECK (octet_length(content_digest) = 32),
    CHECK (
      (status='processing' AND message_id IS NULL) OR
      (status='accepted' AND message_id IS NOT NULL)
    )
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS draft_send_claims_p0 PARTITION OF draft_send_claims FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS draft_send_claims_p1 PARTITION OF draft_send_claims FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS draft_send_claims_p2 PARTITION OF draft_send_claims FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS draft_send_claims_p3 PARTITION OF draft_send_claims FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS draft_send_claims_status_recent
    ON draft_send_claims (account_id, status, updated_at DESC);
