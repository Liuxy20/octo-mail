-- The gateway default account is an internal browser mailbox, not an Agent
-- mailbox. Revoke any legacy Agent binding that targets an active gateway
-- default without deleting the account, address, Inbox, or stored messages.

UPDATE agent_binding_credentials credential
SET revoked_at=now()
FROM agent_bindings binding
JOIN gateway_identities gateway
  ON gateway.default_account_id=binding.account_id
 AND gateway.tenant_id=binding.tenant_id
 AND gateway.owner_principal_id=binding.owner_principal_id
 AND gateway.space_id=binding.space_id
 AND NOT gateway.disabled
WHERE credential.binding_id=binding.id
  AND credential.revoked_at IS NULL;

UPDATE agent_bindings binding
SET status='revoked', revoked_at=now()
FROM gateway_identities gateway
WHERE gateway.default_account_id=binding.account_id
  AND gateway.tenant_id=binding.tenant_id
  AND gateway.owner_principal_id=binding.owner_principal_id
  AND gateway.space_id=binding.space_id
  AND NOT gateway.disabled
  AND binding.status='active';

-- Keep the invariant true when an operator later creates, re-enables, or
-- repoints a gateway identity to an account that already has an Agent binding.
CREATE OR REPLACE FUNCTION revoke_gateway_default_agent_bindings()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.disabled THEN
        RETURN NEW;
    END IF;

    UPDATE agent_binding_credentials credential
    SET revoked_at=now()
    FROM agent_bindings binding
    WHERE credential.binding_id=binding.id
      AND credential.revoked_at IS NULL
      AND binding.account_id=NEW.default_account_id
      AND binding.tenant_id=NEW.tenant_id
      AND binding.owner_principal_id=NEW.owner_principal_id
      AND binding.space_id=NEW.space_id;

    UPDATE agent_bindings binding
    SET status='revoked', revoked_at=now()
    WHERE binding.account_id=NEW.default_account_id
      AND binding.tenant_id=NEW.tenant_id
      AND binding.owner_principal_id=NEW.owner_principal_id
      AND binding.space_id=NEW.space_id
      AND binding.status='active';

    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS gateway_identity_revoke_default_agent_bindings ON gateway_identities;
CREATE TRIGGER gateway_identity_revoke_default_agent_bindings
AFTER INSERT OR UPDATE OF default_account_id, space_id, tenant_id,
    owner_principal_id, disabled ON gateway_identities
FOR EACH ROW EXECUTE FUNCTION revoke_gateway_default_agent_bindings();
