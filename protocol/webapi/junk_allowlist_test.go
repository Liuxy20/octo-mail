package webapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestRestoreNotJunkAddsAccountScopedSenderAllowlist(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, junk_sender_allowlist RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, domainID, accountID, otherAccountID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('junk-allowlist') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'owner') RETURNING id`, &accountID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'other') RETURNING id`, &otherAccountID, tenantID)
	for _, item := range []struct {
		accountID int64
		localpart string
		password  string
	}{
		{accountID, "owner", "owner-password"},
		{otherAccountID, "other", "other-password"},
	} {
		if _, err := s.Pool.Exec(ctx,
			`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,$4)`,
			tenantID, domainID, item.accountID, item.localpart); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(ctx,
			`INSERT INTO principals (tenant_id,login) VALUES ($1,$2)`, tenantID, item.localpart+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "owner@example.com", "owner-password"); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, "other@example.com", "other-password"); err != nil {
		t.Fatal(err)
	}

	recipient, _ := smtp.ParseAddress("owner@example.com")
	target, err := dir.ResolveInbound(ctx, recipient.Path())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: Trusted Sender <Trusted.Sender@Remote.Example>\r\nTo: owner@example.com\r\nSubject: restore\r\nMessage-ID: <restore@example.net>\r\n\r\nbody\r\n")
	if _, err := target.DeliverTo(ctx, "Junk", &store.Message{Flags: store.Flags{Junk: true}}, mem(string(raw))); err != nil {
		t.Fatal(err)
	}
	var emailID int64
	if err := s.Pool.QueryRow(ctx,
		`SELECT COALESCE(email_id,id) FROM messages WHERE account_id=$1 AND NOT expunged ORDER BY id DESC LIMIT 1`, accountID).Scan(&emailID); err != nil {
		t.Fatal(err)
	}

	hs := httptest.NewServer((&webapi.Server{Dir: dir}).Handler())
	defer hs.Close()
	do := func(login, password, method, path string) (int, map[string]any) {
		req, err := http.NewRequest(method, hs.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth(login, password)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("decode %s %s response: %v (%q)", method, path, err, raw)
			}
		}
		return resp.StatusCode, body
	}

	messageID := "E" + strconv.FormatInt(emailID, 10)
	status, restored := do("owner@example.com", "owner-password", http.MethodPost, "/webapi/v0/messages/"+messageID+"/not-junk")
	if status != http.StatusOK || restored["senderAddress"] != "trusted.sender@remote.example" {
		t.Fatalf("restore response = status %d body %#v", status, restored)
	}
	var junkRows, inboxRows int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND COALESCE(m.email_id,m.id)=$2 AND mb.name='Junk' AND NOT m.expunged`, accountID, emailID).Scan(&junkRows); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND COALESCE(m.email_id,m.id)=$2 AND mb.name='Inbox' AND NOT m.expunged AND m.f_notjunk`, accountID, emailID).Scan(&inboxRows); err != nil {
		t.Fatal(err)
	}
	if junkRows != 0 || inboxRows != 1 {
		t.Fatalf("restored mailbox rows: Junk=%d Inbox+NotJunk=%d, want 0/1", junkRows, inboxRows)
	}

	status, ownerList := do("owner@example.com", "owner-password", http.MethodGet, "/webapi/v0/junk-allowlist")
	if status != http.StatusOK {
		t.Fatalf("owner allowlist status = %d", status)
	}
	addresses, _ := ownerList["addresses"].([]any)
	if len(addresses) != 1 || addresses[0] != "trusted.sender@remote.example" {
		t.Fatalf("owner allowlist = %#v", ownerList)
	}
	status, otherList := do("other@example.com", "other-password", http.MethodGet, "/webapi/v0/junk-allowlist")
	if status != http.StatusOK || len(otherList["addresses"].([]any)) != 0 {
		t.Fatalf("other account allowlist = status %d body %#v", status, otherList)
	}

	status, _ = do("owner@example.com", "owner-password", http.MethodDelete,
		"/webapi/v0/junk-allowlist/"+url.PathEscape("trusted.sender@remote.example"))
	if status != http.StatusNoContent {
		t.Fatalf("delete allowlist status = %d", status)
	}
	status, ownerList = do("owner@example.com", "owner-password", http.MethodGet, "/webapi/v0/junk-allowlist")
	if status != http.StatusOK || len(ownerList["addresses"].([]any)) != 0 {
		t.Fatalf("owner allowlist after delete = status %d body %#v", status, ownerList)
	}
}
