-- Authoritative Space ownership for independently stored Agent mailboxes.
--
-- accounts.owner_principal_id identifies the human owner but not the OCTO
-- Space. This relation supplies that missing isolation dimension and is also
-- the source counted by the per-owner/per-Space registration limit.

CREATE TABLE IF NOT EXISTS agent_mailbox_registrations (
    tenant_id          bigint NOT NULL REFERENCES tenants(id),
    account_id         bigint PRIMARY KEY REFERENCES accounts(id),
    owner_principal_id bigint NOT NULL REFERENCES principals(id),
    space_id           text NOT NULL CHECK (btrim(space_id) <> ''),
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_mailbox_registrations_owner_space
    ON agent_mailbox_registrations (tenant_id, owner_principal_id, space_id);

-- Recover the Space of mailboxes that were connected before this relation was
-- introduced. The authorization request is human-approved evidence. When a
-- mailbox was rebound, the latest approval wins. Old unbound mailboxes without
-- such evidence deliberately remain unscoped instead of being exposed in every
-- Space.
INSERT INTO agent_mailbox_registrations
    (tenant_id, account_id, owner_principal_id, space_id, created_at)
SELECT acc.tenant_id, acc.id, acc.owner_principal_id, evidence.space_id,
       COALESCE(evidence.approved_at, evidence.created_at)
FROM accounts acc
JOIN LATERAL (
    SELECT request.space_id, request.approved_at, request.created_at
    FROM agent_auth_requests request
    WHERE request.account_id=acc.id
      AND request.owner_principal_id=acc.owner_principal_id
      AND btrim(request.space_id) <> ''
      AND request.status IN ('approved','exchanged')
    ORDER BY request.approved_at DESC NULLS LAST, request.created_at DESC
    LIMIT 1
) evidence ON true
WHERE acc.owner_principal_id IS NOT NULL
  AND NOT acc.disabled
  AND acc.principal_id IS NOT NULL
  AND acc.principal_id <> acc.owner_principal_id
  AND NOT EXISTS (
      SELECT 1 FROM gateway_identities gateway
      WHERE gateway.default_account_id=acc.id
        AND gateway.tenant_id=acc.tenant_id
        AND gateway.owner_principal_id=acc.owner_principal_id
        AND gateway.space_id=evidence.space_id
        AND NOT gateway.disabled
  )
ON CONFLICT (account_id) DO NOTHING;

-- Older unbound Agent mailboxes have no authorization evidence. If their owner
-- is mapped to exactly one active Space, that single gateway mapping is
-- sufficient to recover their scope without guessing. Owners spanning multiple
-- Spaces remain intentionally unscoped for explicit operator review.
INSERT INTO agent_mailbox_registrations
    (tenant_id, account_id, owner_principal_id, space_id, created_at)
SELECT acc.tenant_id, acc.id, acc.owner_principal_id, owner_space.space_id,
       acc.created_at
FROM accounts acc
JOIN (
    SELECT tenant_id, owner_principal_id, min(space_id) AS space_id
    FROM gateway_identities
    WHERE NOT disabled
    GROUP BY tenant_id, owner_principal_id
    HAVING count(DISTINCT space_id)=1
) owner_space ON owner_space.tenant_id=acc.tenant_id
             AND owner_space.owner_principal_id=acc.owner_principal_id
WHERE acc.owner_principal_id IS NOT NULL
  AND NOT acc.disabled
  -- Independently registered Agent mailboxes have their own mailbox-login
  -- principal. The Space's gateway default is an explicit Agent designation
  -- recorded in gateway_identities and may reuse the owner principal; this
  -- backfill only infers additional mailboxes, so same-principal accounts that
  -- lack that explicit designation must not be inferred as registrations.
  AND acc.principal_id IS NOT NULL
  AND acc.principal_id <> acc.owner_principal_id
  AND NOT EXISTS (
      SELECT 1 FROM gateway_identities gateway
      WHERE gateway.default_account_id=acc.id
        AND gateway.tenant_id=acc.tenant_id
        AND gateway.owner_principal_id=acc.owner_principal_id
        AND NOT gateway.disabled
  )
ON CONFLICT (account_id) DO NOTHING;
