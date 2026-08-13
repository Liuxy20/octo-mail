-- Post-storage Agent Mail product rules.
--
-- These tables are deliberately separate from the inbound `rulesets` security
-- pipeline. Product rules cannot affect SMTP acceptance, authentication, spam
-- classification, or mailbox routing.

CREATE TABLE IF NOT EXISTS mail_rules (
    account_id          bigint NOT NULL REFERENCES accounts(id),
    id                  bigint GENERATED ALWAYS AS IDENTITY,
    name                text NOT NULL,
    enabled             boolean NOT NULL DEFAULT true,
    priority            integer NOT NULL DEFAULT 0,
    match_from          text NOT NULL DEFAULT '',
    match_subject       text NOT NULL DEFAULT '',
    forward_targets     text[] NOT NULL,
    created_by_principal_id bigint NOT NULL REFERENCES principals(id),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, id),
    CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    CHECK (btrim(match_from) <> '' OR btrim(match_subject) <> ''),
    CHECK (cardinality(forward_targets) BETWEEN 1 AND 5)
) PARTITION BY HASH (account_id);

CREATE TABLE IF NOT EXISTS mail_rules_p0 PARTITION OF mail_rules FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS mail_rules_p1 PARTITION OF mail_rules FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS mail_rules_p2 PARTITION OF mail_rules FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS mail_rules_p3 PARTITION OF mail_rules FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS mail_rules_enabled_order
    ON mail_rules (account_id, enabled, priority DESC, id);

CREATE TABLE IF NOT EXISTS mail_rule_executions (
    account_id       bigint NOT NULL,
    id               bigint GENERATED ALWAYS AS IDENTITY,
    rule_id          bigint NOT NULL,
    source_email_id  bigint NOT NULL,
    status           text NOT NULL
                     CHECK (status IN ('matched','queued','partially_queued','failed','loop_blocked')),
    target_results   jsonb NOT NULL DEFAULT '[]'::jsonb,
    hop_count        integer NOT NULL DEFAULT 0 CHECK (hop_count BETWEEN 0 AND 3),
    error_code       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    PRIMARY KEY (account_id, id),
    UNIQUE (account_id, rule_id, source_email_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
) PARTITION BY HASH (account_id);

-- Execution history is an audit record and must survive rule deletion. Drop
-- the development-time FK if this idempotent schema was already applied before
-- that invariant was introduced.
ALTER TABLE mail_rule_executions
    DROP CONSTRAINT IF EXISTS mail_rule_executions_account_id_rule_id_fkey;

CREATE TABLE IF NOT EXISTS mail_rule_executions_p0 PARTITION OF mail_rule_executions FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE IF NOT EXISTS mail_rule_executions_p1 PARTITION OF mail_rule_executions FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE IF NOT EXISTS mail_rule_executions_p2 PARTITION OF mail_rule_executions FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE IF NOT EXISTS mail_rule_executions_p3 PARTITION OF mail_rule_executions FOR VALUES WITH (MODULUS 4, REMAINDER 3);

CREATE INDEX IF NOT EXISTS mail_rule_executions_recent
    ON mail_rule_executions (account_id, created_at DESC, id DESC);
