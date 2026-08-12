-- Gateway designation changes must invalidate credentials whose Space/account
-- authorization no longer exists. The trigger covers the WebAdmin upsert and
-- direct operational SQL without adding a new public management endpoint.

CREATE OR REPLACE FUNCTION revoke_orphaned_gateway_bindings()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_account_id bigint;
    old_space_id text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        old_account_id := OLD.default_account_id;
        old_space_id := OLD.space_id;
    ELSIF OLD.default_account_id IS DISTINCT FROM NEW.default_account_id
       OR OLD.space_id IS DISTINCT FROM NEW.space_id
       OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.owner_principal_id IS DISTINCT FROM NEW.owner_principal_id
       OR (NOT OLD.disabled AND NEW.disabled) THEN
        old_account_id := OLD.default_account_id;
        old_space_id := OLD.space_id;
    ELSE
        RETURN NEW;
    END IF;

    UPDATE agent_binding_credentials credential
    SET revoked_at=now()
    WHERE credential.revoked_at IS NULL
      AND credential.binding_id IN (
          SELECT binding.id
          FROM agent_bindings binding
          WHERE binding.account_id=old_account_id
            AND binding.space_id=old_space_id
            AND binding.status='active'
            AND NOT EXISTS (
                SELECT 1 FROM agent_mailbox_registrations registration
                WHERE registration.account_id=binding.account_id
                  AND registration.tenant_id=binding.tenant_id
                  AND registration.owner_principal_id=binding.owner_principal_id
                  AND registration.space_id=binding.space_id
            )
            AND NOT EXISTS (
                SELECT 1 FROM gateway_identities gateway
                WHERE gateway.default_account_id=binding.account_id
                  AND gateway.tenant_id=binding.tenant_id
                  AND gateway.owner_principal_id=binding.owner_principal_id
                  AND gateway.space_id=binding.space_id
                  AND NOT gateway.disabled
            )
      );

    UPDATE agent_bindings binding
    SET status='revoked', revoked_at=now()
    WHERE binding.account_id=old_account_id
      AND binding.space_id=old_space_id
      AND binding.status='active'
      AND NOT EXISTS (
          SELECT 1 FROM agent_mailbox_registrations registration
          WHERE registration.account_id=binding.account_id
            AND registration.tenant_id=binding.tenant_id
            AND registration.owner_principal_id=binding.owner_principal_id
            AND registration.space_id=binding.space_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM gateway_identities gateway
          WHERE gateway.default_account_id=binding.account_id
            AND gateway.tenant_id=binding.tenant_id
            AND gateway.owner_principal_id=binding.owner_principal_id
            AND gateway.space_id=binding.space_id
            AND NOT gateway.disabled
      );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS gateway_identity_revoke_orphaned_bindings ON gateway_identities;
CREATE TRIGGER gateway_identity_revoke_orphaned_bindings
AFTER UPDATE OR DELETE ON gateway_identities
FOR EACH ROW EXECUTE FUNCTION revoke_orphaned_gateway_bindings();
