-- Durable recipient delivery results linked to Sent messages.
-- Kept as an additive schema step so the original queue schema remains intact.

ALTER TABLE queue
    ADD COLUMN IF NOT EXISTS message_id bigint;

ALTER TABLE queue_log
    ADD COLUMN IF NOT EXISTS message_id bigint;

CREATE TABLE IF NOT EXISTS outbound_deliveries (
    account_id       bigint NOT NULL REFERENCES accounts(id),
    queue_id         bigint NOT NULL,
    message_id       bigint NOT NULL,
    recipient        text NOT NULL,
    status           text NOT NULL DEFAULT 'queued',
    attempt_count    int NOT NULL DEFAULT 0,
    smtp_code        int NOT NULL DEFAULT 0,
    smtp_secode      text NOT NULL DEFAULT '',
    reason_code      text NOT NULL DEFAULT '',
    technical_detail text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_attempt_at  timestamptz,
    delivered_at     timestamptz,
    failed_at        timestamptz,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, queue_id),
    FOREIGN KEY (account_id, message_id)
        REFERENCES messages (account_id, id) ON DELETE CASCADE
) PARTITION BY HASH (account_id);

-- Replace the initial development constraint in databases that created this
-- table before delivery rows followed Sent-message garbage collection.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'outbound_deliveries_account_id_message_id_fkey'
          AND conrelid = 'outbound_deliveries'::regclass
          AND confdeltype = 'c'
    ) THEN
        ALTER TABLE outbound_deliveries
            DROP CONSTRAINT IF EXISTS outbound_deliveries_account_id_message_id_fkey;
        ALTER TABLE outbound_deliveries
            ADD CONSTRAINT outbound_deliveries_account_id_message_id_fkey
            FOREIGN KEY (account_id, message_id)
            REFERENCES messages (account_id, id) ON DELETE CASCADE;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS outbound_deliveries_p0
    PARTITION OF outbound_deliveries FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS outbound_deliveries_p1
    PARTITION OF outbound_deliveries FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS outbound_deliveries_p2
    PARTITION OF outbound_deliveries FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS outbound_deliveries_p3
    PARTITION OF outbound_deliveries FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS outbound_deliveries_message_idx
    ON outbound_deliveries (account_id, message_id, queue_id);
