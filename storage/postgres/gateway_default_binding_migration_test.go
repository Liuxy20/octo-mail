package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/security/auth"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestGatewayDefaultBindingMigrationRevokesOnlyInternalDefault(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, domainID, ownerPrincipalID, defaultAccountID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('default-binding-migration') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'migration.test') RETURNING id`, tenantID).Scan(&domainID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@migration.test') RETURNING id`, tenantID).Scan(&ownerPrincipalID))
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$2,'owner-default') RETURNING id`, tenantID, ownerPrincipalID).Scan(&defaultAccountID))
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart)
		 VALUES ($1,$2,$3,'owner')`, tenantID, domainID, defaultAccountID)
	must(t, err)
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','owner','space-a',$1,$2,$3)`,
		tenantID, ownerPrincipalID, defaultAccountID)
	must(t, err)
	// Legacy data can contain both designations. Being the active gateway default
	// must win and revoke the Agent binding even when a registration remains.
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO agent_mailbox_registrations
		 (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,'space-a')`, tenantID, defaultAccountID, ownerPrincipalID)
	must(t, err)

	var agentPrincipalID, agentAccountID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent@migration.test') RETURNING id`, tenantID).Scan(&agentPrincipalID))
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$3,'agent-mailbox:agent@migration.test') RETURNING id`,
		tenantID, agentPrincipalID, ownerPrincipalID).Scan(&agentAccountID))
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart)
		 VALUES ($1,$2,$3,'agent')`, tenantID, domainID, agentAccountID)
	must(t, err)
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO agent_mailbox_registrations
		 (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,'space-a')`, tenantID, agentAccountID, ownerPrincipalID)
	must(t, err)

	insertBinding := func(accountID int64, prefix string, credential []byte) int64 {
		t.Helper()
		var bindingID int64
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO agent_bindings
			 (tenant_id,account_id,owner_principal_id,space_id,bot_id)
			 VALUES ($1,$2,$3,'space-a',$4) RETURNING id`,
			tenantID, accountID, ownerPrincipalID, prefix).Scan(&bindingID))
		_, err := s.Pool.Exec(ctx,
			`INSERT INTO agent_binding_credentials (binding_id,key_prefix,cred)
			 VALUES ($1,$2,$3)`, bindingID, prefix, credential)
		must(t, err)
		return bindingID
	}
	defaultPrefix, defaultSecret, err := newAPIKeyToken()
	must(t, err)
	defaultHash, err := auth.HashAPIKey(defaultSecret)
	must(t, err)
	defaultCredential, err := defaultHash.Marshal()
	must(t, err)
	defaultBindingID := insertBinding(defaultAccountID, defaultPrefix, defaultCredential)
	agentBindingID := insertBinding(agentAccountID, "agent-prefix", []byte(`{}`))

	if _, _, _, _, err := s.NewDirectory().AuthenticateAgentCredential(ctx, "omb_"+defaultPrefix+"_"+defaultSecret); err == nil {
		t.Fatal("gateway default Agent credential authenticated before migration")
	}

	ddl, err := schemaFS.ReadFile("schema/25_gateway_default_not_agent.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Pool.Exec(ctx, string(ddl)); err != nil {
			t.Fatalf("apply migration pass %d: %v", i+1, err)
		}
	}

	var defaultStatus, agentStatus string
	var defaultCredentialRevoked, agentCredentialRevoked bool
	must(t, s.Pool.QueryRow(ctx,
		`SELECT status FROM agent_bindings WHERE id=$1`, defaultBindingID).Scan(&defaultStatus))
	must(t, s.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM agent_binding_credentials WHERE binding_id=$1`, defaultBindingID).Scan(&defaultCredentialRevoked))
	must(t, s.Pool.QueryRow(ctx,
		`SELECT status FROM agent_bindings WHERE id=$1`, agentBindingID).Scan(&agentStatus))
	must(t, s.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM agent_binding_credentials WHERE binding_id=$1`, agentBindingID).Scan(&agentCredentialRevoked))
	if defaultStatus != "revoked" || !defaultCredentialRevoked {
		t.Fatalf("default binding status=%q credentialRevoked=%v, want revoked/true", defaultStatus, defaultCredentialRevoked)
	}
	if agentStatus != "active" || agentCredentialRevoked {
		t.Fatalf("registered Agent binding status=%q credentialRevoked=%v, want active/false", agentStatus, agentCredentialRevoked)
	}

	var defaultAccountExists, defaultAddressExists bool
	must(t, s.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND NOT disabled)`, defaultAccountID).Scan(&defaultAccountExists))
	must(t, s.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM addresses WHERE account_id=$1)`, defaultAccountID).Scan(&defaultAddressExists))
	if !defaultAccountExists || !defaultAddressExists {
		t.Fatalf("migration removed default mailbox account=%v address=%v", defaultAccountExists, defaultAddressExists)
	}

	// Repointing the gateway default later must enforce the same invariant
	// immediately, rather than waiting for the next process startup.
	_, err = s.Pool.Exec(ctx,
		`UPDATE gateway_identities SET default_account_id=$1,updated_at=now()
		 WHERE issuer='octo-server' AND subject='owner' AND space_id='space-a'`,
		agentAccountID)
	must(t, err)
	must(t, s.Pool.QueryRow(ctx,
		`SELECT status FROM agent_bindings WHERE id=$1`, agentBindingID).Scan(&agentStatus))
	must(t, s.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM agent_binding_credentials WHERE binding_id=$1`, agentBindingID).Scan(&agentCredentialRevoked))
	if agentStatus != "revoked" || !agentCredentialRevoked {
		t.Fatalf("repointed default binding status=%q credentialRevoked=%v, want revoked/true", agentStatus, agentCredentialRevoked)
	}
}
