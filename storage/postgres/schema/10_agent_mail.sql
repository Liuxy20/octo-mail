-- Agent mailbox ownership.
--
-- One authenticated principal may own multiple independent mail accounts. The
-- account remains the isolation boundary for messages, folders, quota, and API
-- credentials. principal_id is the mailbox login identity; owner_principal_id
-- groups mailboxes for the human management surface.

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS owner_principal_id bigint REFERENCES principals(id);

CREATE INDEX IF NOT EXISTS accounts_principal
	ON accounts (tenant_id, owner_principal_id)
	WHERE owner_principal_id IS NOT NULL;

-- Backfill installations provisioned before account ownership was wired. A
-- non-alias address is the account's primary address and its matching principal
-- is therefore the legacy owner.
UPDATE accounts acc
SET principal_id = COALESCE(acc.principal_id, p.id),
    owner_principal_id = COALESCE(acc.owner_principal_id, p.id)
FROM addresses addr
JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
JOIN principals p ON p.tenant_id=addr.tenant_id
    AND p.login=addr.localpart || '@' || dom.domain
WHERE acc.id=addr.account_id
  AND acc.tenant_id=addr.tenant_id
  AND NOT addr.is_alias
  AND (acc.principal_id IS NULL OR acc.owner_principal_id IS NULL);
