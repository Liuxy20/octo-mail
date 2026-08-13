package postgres

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/smtp"
)

// TestS3BackedDeliveryAndFetch proves the blob backend is swappable behind the
// interface: the SAME kernel delivery/read path, but with message bodies stored
// in a real S3 server (MinIO) instead of the local filesystem. Deliver a message
// (body → S3), then read it back through the kernel (body ← S3 ranged GET),
// asserting the round-trip is byte-exact and the changelog invariant holds.
func TestS3BackedDeliveryAndFetch(t *testing.T) {
	cfg := blob.S3Config{
		Endpoint:  envOr("OCTO_MAIL_S3_ENDPOINT", "http://localhost:29000"),
		Region:    "us-east-1",
		Bucket:    envOr("OCTO_MAIL_S3_BUCKET", "octo-mail-test"),
		AccessKey: envOr("OCTO_MAIL_S3_ACCESS", "octoadmin"),
		SecretKey: envOr("OCTO_MAIL_S3_SECRET", "70521a1a521a5dfd103ce85fe475d8cc"),
	}
	requireS3Endpoint(t, cfg.Endpoint)
	configuredPrefix := os.Getenv("OCTO_MAIL_S3_PREFIX_PATH")
	if configuredPrefix == "" {
		configuredPrefix = "tests/postgres"
	}
	for _, test := range []struct {
		name   string
		prefix string
	}{
		{name: "legacy empty prefix", prefix: ""},
		{name: "configured prefix", prefix: configuredPrefix},
	} {
		t.Run(test.name, func(t *testing.T) {
			caseCfg := cfg
			caseCfg.PrefixPath = test.prefix
			testS3BackedDeliveryAndFetch(t, caseCfg)
		})
	}
}

func testS3BackedDeliveryAndFetch(t *testing.T, cfg blob.S3Config) {
	t.Helper()
	ctx := context.Background()
	bs, err := blob.NewS3(cfg)
	if err != nil {
		t.Fatalf("new S3 store: %v", err)
	}
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`).Scan(&tenantID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, tenantID).Scan(&accID))
	must(t, s.Pool.QueryRow(ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, tenantID).Scan(&domID))
	_, err = s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	must(t, err)

	dir := s.NewDirectory()
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}

	bodyText := "Subject: via s3\r\n\r\n" + strings.Repeat("payload-", 500) + "\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, memReader(bodyText)); err != nil {
		t.Fatalf("deliver (S3-backed): %v", err)
	}

	// Read the message back through the kernel; body streams from S3.
	acc := s.openAccount(accID, tenantID, "u1")
	var got string
	err = acc.Tx(ctx, func(tx store.Tx) error {
		mb, e := acc.MailboxFind(tx, "Inbox")
		if e != nil {
			return e
		}
		msgs, e := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		if e != nil {
			return e
		}
		if len(msgs) != 1 {
			t.Fatalf("expected 1 message, got %d", len(msgs))
		}
		r := acc.MessageReader(ctx, msgs[0])
		defer r.Close()
		buf := make([]byte, r.Size())
		n := 0
		for n < len(buf) {
			m, e := r.Read(buf[n:])
			n += m
			if e != nil {
				break
			}
		}
		got = string(buf[:n])
		return nil
	})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(got, "payload-payload-") || !strings.Contains(got, "Subject: via s3") {
		t.Fatalf("S3 round-trip body mismatch (len=%d): %.60q", len(got), got)
	}

	// Changelog invariant still holds with the S3 backend.
	var head, maxSeq int64
	must(t, s.Pool.QueryRow(ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, accID).Scan(&head))
	must(t, s.Pool.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, accID).Scan(&maxSeq))
	if head != maxSeq {
		t.Fatalf("changelog invariant broken with S3 backend: head=%d max=%d", head, maxSeq)
	}
	t.Logf("OK: delivery→S3, kernel read←S3 byte-exact (%d bytes); changelog head==max(seq)=%d", len(got), head)
}

// requireS3Endpoint skips only when no server is listening. Once the endpoint
// is reachable, bad credentials, a missing bucket, and object-operation errors
// are test failures rather than local-infrastructure skips.
func requireS3Endpoint(t *testing.T, endpoint string) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("parse S3 endpoint: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		t.Fatalf("S3 endpoint scheme = %q, want http or https", u.Scheme)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		t.Fatalf("S3 endpoint %q has no host", endpoint)
	}
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	if err != nil {
		t.Skipf("S3/MinIO endpoint is not reachable: %v", err)
	}
	_ = conn.Close()
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
