package postgres

import (
	"context"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestMailRuleHopConstraintUpgradesOnce(t *testing.T) {
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

	if _, err := s.Pool.Exec(ctx, `TRUNCATE mail_rule_executions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `
		ALTER TABLE mail_rule_executions DROP CONSTRAINT mail_rule_executions_hop_count_check;
		ALTER TABLE mail_rule_executions ADD CONSTRAINT mail_rule_executions_hop_count_check
			CHECK (hop_count BETWEEN 0 AND 3)`); err != nil {
		t.Fatal(err)
	}
	ddl, err := schemaFS.ReadFile("schema/13_mail_rules.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatalf("upgrade legacy hop constraint: %v", err)
	}

	var constraintOID uint32
	var definition string
	if err := s.Pool.QueryRow(ctx, `
		SELECT oid, pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid='mail_rule_executions'::regclass
		   AND conname='mail_rule_executions_hop_count_check'`).Scan(&constraintOID, &definition); err != nil {
		t.Fatal(err)
	}
	if definition != "CHECK ((hop_count >= 0))" {
		t.Fatalf("upgraded hop constraint = %q", definition)
	}

	if _, err := s.Pool.Exec(ctx, string(ddl)); err != nil {
		t.Fatalf("reapply mail rule schema: %v", err)
	}
	var reappliedOID uint32
	if err := s.Pool.QueryRow(ctx, `
		SELECT oid
		  FROM pg_constraint
		 WHERE conrelid='mail_rule_executions'::regclass
		   AND conname='mail_rule_executions_hop_count_check'`).Scan(&reappliedOID); err != nil {
		t.Fatal(err)
	}
	if reappliedOID != constraintOID {
		t.Fatalf("current hop constraint was rebuilt on schema replay: oid %d -> %d", constraintOID, reappliedOID)
	}
}
