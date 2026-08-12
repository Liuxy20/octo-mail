package smtpd_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/protocol/smtpd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

func TestMailRulesRunOnceForMultipleAddressesOfSameAccount(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, accountID, domainID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-dedupe') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'shared') RETURNING id`, &accountID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart,is_alias)
		 VALUES ($1,$2,$3,'primary',false),($1,$2,$3,'alias',true)`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	processed := 0
	mx := &smtpd.Server{
		Dir: s.NewDirectory(), Hostname: "mx.example.com",
		MailRuleProcessor: func(_ context.Context, gotAccountID, sourceEmailID int64, raw []byte) {
			if gotAccountID != accountID || sourceEmailID <= 0 || !strings.Contains(string(raw), "dedupe body") {
				t.Errorf("unexpected rule input account=%d email=%d raw=%q", gotAccountID, sourceEmailID, raw)
			}
			mu.Lock()
			processed++
			mu.Unlock()
		},
	}
	client, server := net.Pipe()
	go func() { _ = mx.Serve(ctx, server) }()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	reader := newLineReader(client)
	_ = reader.line()
	writeSMTPLine(t, client, reader, "EHLO client.example", "250")
	writeSMTPLine(t, client, reader, "MAIL FROM:<sender@remote.example>", "250")
	writeSMTPLine(t, client, reader, "RCPT TO:<primary@example.com>", "250")
	writeSMTPLine(t, client, reader, "RCPT TO:<alias@example.com>", "250")
	writeSMTPLine(t, client, reader, "DATA", "354")
	if _, err := client.Write([]byte("From: sender@remote.example\r\nTo: primary@example.com\r\nSubject: dedupe\r\nMessage-ID: <dedupe@remote.example>\r\n\r\ndedupe body\r\n.\r\n")); err != nil {
		t.Fatal(err)
	}
	if line := reader.line(); !strings.HasPrefix(line, "250") {
		t.Fatalf("DATA response = %q, want 250", line)
	}

	var inboxCopies int
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND mb.name='Inbox' AND NOT m.expunged`, accountID).Scan(&inboxCopies); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	ruleRuns := processed
	mu.Unlock()
	if inboxCopies != 2 || ruleRuns != 1 {
		t.Fatalf("Inbox copies/rule runs = %d/%d, want 2/1", inboxCopies, ruleRuns)
	}
}

func writeSMTPLine(t *testing.T, client net.Conn, reader *lineReader, command, prefix string) {
	t.Helper()
	if _, err := client.Write([]byte(command + "\r\n")); err != nil {
		t.Fatal(err)
	}
	for {
		line := reader.line()
		if !strings.HasPrefix(line, prefix) {
			t.Fatalf("%s response = %q, want %s", command, line, prefix)
		}
		if len(line) < 4 || line[3] == ' ' {
			return
		}
	}
}
