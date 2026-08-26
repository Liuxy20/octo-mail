package smtpd_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

// TestRulesetAndJunkRouting proves that a per-account ruleset can force a
// mailbox, while known-bad reputation remains reversible Junk routing.
func TestRulesetAndJunkRouting(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, greylist, inbound_reputation, rulesets RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	dir := s.NewDirectory()

	deliver := func(mx *smtpd.Server, from, raw string) error {
		cConn, sConn := net.Pipe()
		lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 3000}}
		go func() { _ = mx.Serve(ctx, lc) }()
		_ = cConn.SetDeadline(time.Now().Add(20 * time.Second))
		cl, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "client.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			return err
		}
		defer cl.Close()
		return cl.Deliver(ctx, from, "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false)
	}

	// === Part 1: ruleset forces a List-Id message into the "Lists" mailbox. ===
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO rulesets (account_id, header_name, header_substr, mailbox, force_accept, ord)
		 VALUES ($1,'List-Id','announce.example','Lists',true,0)`, accID); err != nil {
		t.Fatal(err)
	}
	decider := &inbound.Decider{Pool: s.Pool}
	mx := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Decider: decider}

	raw := "From: news@announce.example\r\nTo: u1@example.com\r\n" +
		"List-Id: <list.announce.example>\r\nSubject: newsletter\r\n\r\nhi\r\n"
	if err := deliver(mx, "news@announce.example", raw); err != nil {
		t.Fatalf("ruleset delivery failed: %v", err)
	}
	var listCount int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Lists' AND NOT m.expunged`, accID).Scan(&listCount)
	if listCount != 1 {
		t.Fatalf("ruleset did not file into Lists: got %d", listCount)
	}

	// === Part 2: known-bad reputation is filed into Junk without rejecting or
	// challenging the sender. ===
	if _, err := s.Pool.Exec(ctx, `INSERT INTO inbound_reputation (account_id, sender_domain, junk_count) VALUES ($1,'stranger.example',5)`, accID); err != nil {
		t.Fatal(err)
	}
	spDecider := &inbound.Decider{Pool: s.Pool}
	spMX := &smtpd.Server{Dir: dir, Hostname: "mx.example.com", Decider: spDecider}

	raw2 := "From: cold@stranger.example\r\nTo: u1@example.com\r\nSubject: please read\r\n\r\nlet me in\r\n"
	if err := deliver(spMX, "cold@stranger.example", raw2); err != nil {
		t.Fatalf("known-bad sender was challenged/rejected instead of accepted into Junk: %v", err)
	}
	var junk int
	s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name='Junk' AND NOT m.expunged`, accID).Scan(&junk)
	if junk != 1 {
		t.Fatalf("known-bad message count in Junk = %d, want 1", junk)
	}

	t.Logf("OK: ruleset filed List-Id mail into Lists; known-bad reputation filed mail into Junk")
}
