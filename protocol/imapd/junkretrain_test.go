package imapd_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/imapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/imapclient"
)

// TestJunkFlagDoesNotTrainAccountModel proves that normal mailbox organization
// stays separate from the deployment-wide classifier. Marking a message \Junk
// changes only the message flag and never writes account-local Bayesian state.
func TestJunkFlagDoesNotTrainAccountModel(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, junk_words, junk_totals RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accountID, domainID int64
	mustScan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('junk-flag') RETURNING id`, &tenantID)
	mustScan(t, s, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'u1') RETURNING id`, &accountID, tenantID)
	mustScan(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'u1')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,'u1@example.com')`, tenantID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	target, err := dir.ResolveInbound(ctx, mustAddr(t, "u1@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, memReader("Subject: test\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	clientConn, serverConn := net.Pipe()
	go func() { _ = (&imapd.Server{Dir: dir}).Serve(ctx, serverConn) }()
	_ = clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	client, err := imapclient.New(clientConn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Login("u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Select("INBOX"); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteCommandf("", "uid store 1 +FLAGS (\\Junk)"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatal(err)
	}

	var junkFlags, accountWords, accountTotals int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE account_id=$1 AND f_junk`, accountID).Scan(&junkFlags); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM junk_words WHERE account_id=$1`, accountID).Scan(&accountWords); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM junk_totals WHERE account_id=$1`, accountID).Scan(&accountTotals); err != nil {
		t.Fatal(err)
	}
	if junkFlags != 1 || accountWords != 0 || accountTotals != 0 {
		t.Fatalf("after STORE: junk flags=%d words=%d totals=%d, want 1/0/0", junkFlags, accountWords, accountTotals)
	}
}
