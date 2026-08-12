-- Preserve the normalized source text beside the existing tsvector so mailbox
-- search can provide exact, case-insensitive substring matching for Chinese and
-- other languages that are not segmented by PostgreSQL's simple dictionary.
ALTER TABLE fts
    ADD COLUMN IF NOT EXISTS search_text text;

ALTER TABLE fts
    ALTER COLUMN search_text DROP DEFAULT,
    ALTER COLUMN search_text DROP NOT NULL;

-- Upgrade backfill scans only rows that still need decoded source text. Once
-- complete this partial index is empty, so steady-state checks stay cheap.
CREATE INDEX IF NOT EXISTS fts_search_text_backfill_idx
    ON fts (account_id, message_id)
    WHERE search_text IS NULL;
