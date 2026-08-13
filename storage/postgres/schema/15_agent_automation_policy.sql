-- Human-approved, mailbox-scoped automation policy.
--
-- The automatic-send scope is deliberately narrow: owner-directed plain-text
-- new messages and plain-text replies to the original sender. Reply-all,
-- forwarding, attachments, HTML, and destructive operations continue to
-- require owner review or confirmation.

ALTER TABLE agent_auth_requests
    ADD COLUMN IF NOT EXISTS auto_reply_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE agent_bindings
    ADD COLUMN IF NOT EXISTS auto_reply_enabled boolean NOT NULL DEFAULT false;

-- The product-level policy now covers both owner-directed new messages and
-- ordinary replies. Keep the legacy boolean during the local compatibility
-- window, but make this enum the authoritative decision input.
ALTER TABLE agent_auth_requests
    ADD COLUMN IF NOT EXISTS outbound_mode text NOT NULL DEFAULT 'manual_confirmation'
    CHECK (outbound_mode IN ('manual_confirmation','automatic_send'));

ALTER TABLE agent_bindings
    ADD COLUMN IF NOT EXISTS outbound_mode text NOT NULL DEFAULT 'manual_confirmation'
    CHECK (outbound_mode IN ('manual_confirmation','automatic_send'));

UPDATE agent_auth_requests
SET outbound_mode='automatic_send'
WHERE auto_reply_enabled AND outbound_mode='manual_confirmation';

UPDATE agent_bindings
SET outbound_mode='automatic_send'
WHERE auto_reply_enabled AND outbound_mode='manual_confirmation';
