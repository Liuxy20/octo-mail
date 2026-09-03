-- ---------------------------------------------------------------------------
-- Junk (bayesian spam) filter — deployment baseline and sender allowlist
-- ---------------------------------------------------------------------------
-- A deployment-wide baseline supplies content classification for
-- every account. Runtime mailbox actions do not train private word statistics.
-- This state MUST be shared across nodes, so the counts live in PostgreSQL
-- rather than per-node files.
--
-- junk_words and junk_totals are retained for backwards-compatible rollback of
-- existing installations. The production receive path no longer reads or
-- updates these account-local counters.
CREATE TABLE IF NOT EXISTS junk_words (
    account_id bigint NOT NULL,
    word       text   NOT NULL,
    ham        bigint NOT NULL DEFAULT 0,
    spam       bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, word)
);

CREATE TABLE IF NOT EXISTS junk_totals (
    account_id bigint NOT NULL PRIMARY KEY,
    hams       bigint NOT NULL DEFAULT 0,
    spams      bigint NOT NULL DEFAULT 0
);

-- The deployment-wide classifier is deliberately not attached to a tenant or
-- to the reserved system account. Its aggregate model is used as a baseline
-- for every recipient account. Keeping it in separate tables
-- makes the cross-tenant boundary explicit and prevents account_id=0 or another
-- magic account from becoming an accidental capability.
-- word is a deterministic SHA-256 feature identifier for the global model.
CREATE TABLE IF NOT EXISTS junk_global_words (
    word text PRIMARY KEY,
    ham  bigint NOT NULL DEFAULT 0,
    spam bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS junk_global_totals (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    hams      bigint NOT NULL DEFAULT 0,
    spams     bigint NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS junk_global_learns (
    sample_id  text PRIMARY KEY,
    ham        boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Exact sender addresses explicitly trusted by the owner of one account.
-- The SMTP path only applies this bypass when the visible From identity passes
-- DMARC alignment, so a spoofed From value cannot claim an allowlist entry.
CREATE TABLE IF NOT EXISTS junk_sender_allowlist (
    account_id     bigint NOT NULL,
    sender_address text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, sender_address)
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p0 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p1 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p2 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS junk_sender_allowlist_p3 PARTITION OF junk_sender_allowlist FOR VALUES WITH (MODULUS 4, REMAINDER 3);
