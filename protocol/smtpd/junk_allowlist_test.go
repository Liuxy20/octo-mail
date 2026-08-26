package smtpd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/inbound"
	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/smtpclient"
)

type alwaysJunkClassifier struct{}

func (alwaysJunkClassifier) Classify(context.Context, int64, []byte) (float64, bool, bool, error) {
	return 1, true, true, nil
}

type exactSenderAllowlist string

func (a exactSenderAllowlist) SenderAllowed(_ context.Context, _ int64, sender string) (bool, error) {
	return strings.EqualFold(string(a), sender), nil
}

func TestJunkAllowlistRequiresDMARCAuthenticatedFrom(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, inbound_reputation, rulesets RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accountID, domainID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('allowlist-auth') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'u1') RETURNING id`, &accountID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'u1')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"sender.example.":                {"v=spf1 ip4:10.0.0.9 -all"},
			"sel._domainkey.sender.example.": {"v=DKIM1;k=ed25519;p=" + base64.StdEncoding.EncodeToString(pub)},
			"_dmarc.sender.example.":         {"v=DMARC1; p=reject"},
		},
		AllAuthentic: true,
	}
	mx := &smtpd.Server{
		Dir:           s.NewDirectory(),
		Hostname:      "mx.example.com",
		Auth:          &inbound.Authenticator{Resolver: resolver},
		Decider:       &inbound.Decider{Pool: s.Pool},
		Junk:          alwaysJunkClassifier{},
		JunkAllowlist: exactSenderAllowlist("bob@sender.example"),
	}
	deliver := func(mailFrom, raw string) error {
		cConn, sConn := net.Pipe()
		lc := &ipConn{Conn: sConn, remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 12345}}
		go func() { _ = mx.Serve(ctx, lc) }()
		_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
		client, err := smtpclient.New(ctx, nil, cConn, smtpclient.TLSSkip, false,
			dns.Domain{ASCII: "mail.sender.example"}, dns.Domain{ASCII: "mx.example.com"}, smtpclient.Opts{})
		if err != nil {
			return err
		}
		defer client.Close()
		return client.Deliver(ctx, mailFrom, "u1@example.com", int64(len(raw)), strings.NewReader(raw), false, false, false)
	}

	body := "From: bob@sender.example\r\nTo: u1@example.com\r\nSubject: authenticated\r\nDate: Wed, 01 Jul 2026 10:00:00 +0000\r\nMessage-Id: <authenticated@sender.example>\r\n\r\ncontent classifier says junk\r\n"
	selector := dkim.Selector{Hash: "sha256", HeaderRelaxed: true, BodyRelaxed: true,
		Headers: []string{"From", "To", "Subject", "Date", "Message-Id"}, PrivateKey: priv, Domain: dns.Domain{ASCII: "sel"}}
	header, err := dkim.Sign(ctx, nil, smtp.Localpart("bob"), dns.Domain{ASCII: "sender.example"}, []dkim.Selector{selector}, false, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := deliver("bob@sender.example", header+body); err != nil {
		t.Fatalf("authenticated allowlisted delivery: %v", err)
	}

	// The visible From is identical, but the message is unsigned and its envelope
	// sender is unrelated. It must not inherit the allowlist bypass.
	forged := "From: bob@sender.example\r\nTo: u1@example.com\r\nSubject: forged\r\nMessage-Id: <forged@attacker.example>\r\n\r\ncontent classifier says junk\r\n"
	if err := deliver("attacker@attacker.example", forged); err != nil {
		t.Fatalf("forged message should be accepted into Junk, not rejected: %v", err)
	}

	count := func(mailbox string) int {
		var n int
		if err := s.Pool.QueryRow(ctx,
			`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND mb.name=$2 AND NOT m.expunged`,
			accountID, mailbox).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if inbox, junk := count("Inbox"), count("Junk"); inbox != 1 || junk != 1 {
		t.Fatalf("mailbox counts: Inbox=%d Junk=%d, want 1/1", inbox, junk)
	}
}
