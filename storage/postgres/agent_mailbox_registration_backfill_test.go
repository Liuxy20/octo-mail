package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestAgentMailboxRegistrationBackfillOnlyIncludesActiveIndependentMailboxes(t *testing.T) {
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

	var tenantID, ownerPrincipalID, agentPrincipalID, disabledPrincipalID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('agent-registration-backfill') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@backfill.test') RETURNING id`, tenantID).Scan(&ownerPrincipalID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent@backfill.test') RETURNING id`, tenantID).Scan(&agentPrincipalID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'disabled@backfill.test') RETURNING id`, tenantID).Scan(&disabledPrincipalID))

	insertAccount := func(name string, principalID int64, disabled bool) int64 {
		var id int64
		must(t, s.Pool.QueryRow(ctx,
			`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name,disabled)
			 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
			tenantID, principalID, ownerPrincipalID, name, disabled).Scan(&id))
		return id
	}
	ownerAccountID := insertAccount("owner", ownerPrincipalID, false)
	ordinarySecondaryID := insertAccount("ordinary-secondary", ownerPrincipalID, false)
	var noLoginIdentityID int64
	must(t, s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,NULL,$2,'generic-no-login') RETURNING id`, tenantID, ownerPrincipalID).Scan(&noLoginIdentityID))
	agentEvidenceID := insertAccount("agent-evidence", agentPrincipalID, false)
	agentFallbackID := insertAccount("agent-fallback", agentPrincipalID, false)
	disabledAgentID := insertAccount("agent-disabled", disabledPrincipalID, true)

	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','owner','space-a',$1,$2,$3)`,
		tenantID, ownerPrincipalID, ownerAccountID); err != nil {
		t.Fatal(err)
	}
	insertEvidence := func(hashHex, userCode string, accountID int64) {
		_, err := s.Pool.Exec(ctx,
			`INSERT INTO agent_auth_requests
			 (device_hash,user_code,bot_id,space_id,code_challenge,status,owner_principal_id,account_id,expires_at,approved_at)
			 VALUES (decode($1,'hex'),$2,'bot','space-a','challenge','approved',$3,$4,now()+interval '1 hour',now())`,
			hashHex, userCode, ownerPrincipalID, accountID)
		must(t, err)
	}
	insertEvidence("01", "EVID01", agentEvidenceID)
	insertEvidence("02", "EVID02", ordinarySecondaryID)
	insertEvidence("03", "EVID03", disabledAgentID)
	insertEvidence("04", "EVID04", noLoginIdentityID)

	if _, err := s.Pool.Exec(ctx, `DELETE FROM agent_mailbox_registrations`); err != nil {
		t.Fatal(err)
	}
	ddl, err := schemaFS.ReadFile("schema/20_agent_mailbox_registrations.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatalf("replay Agent mailbox registration backfill: %v", err)
	}

	rows, err := s.Pool.Query(ctx, `SELECT account_id FROM agent_mailbox_registrations ORDER BY account_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []int64{agentEvidenceID, agentFallbackID}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("backfilled account ids = %v, want active independent Agent mailboxes %v", got, want)
	}
}
