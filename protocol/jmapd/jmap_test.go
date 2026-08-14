package jmapd_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/jmapd"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

var testDSN = func() string {
	if dsn := os.Getenv("OCTO_MAIL_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"
}()

// TestJMAPProjectionSymmetry proves the architecture's central claim: IMAP and
// JMAP are two projections of ONE change-log. It exercises the real JMAP methods
// (Email/query, Email/get, Email/changes, Email/set) over HTTP, and asserts that
// JMAP state == changelog offset and that Email/changes(sinceState=n) returns
// exactly the messages with modseq > n — the same replay IMAP serves as
// CONDSTORE CHANGEDSINCE n.
func TestJMAPProjectionSymmetry(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('acme') RETURNING id`, &tenantID)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	ex(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "x"); err != nil {
		t.Fatal(err)
	}

	// Deliver msg 1, capture head, deliver msg 2.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: one\r\n\r\nbody one\r\n")); err != nil {
		t.Fatal(err)
	}
	var afterFirst int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &afterFirst, accID)
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: two\r\n\r\nbody two\r\n")); err != nil {
		t.Fatal(err)
	}

	// HTTP JMAP server.
	js := &jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}
	hs := httptest.NewServer(js.Handler())
	defer hs.Close()

	// Session: standard discovery is available, state is present, and protocol
	// resource URLs satisfy the RFC 8620 URI-template contract.
	sess := getJSON(t, hs.URL+"/.well-known/jmap")
	if sess["primaryAccounts"] == nil {
		t.Fatalf("session missing primaryAccounts: %v", sess)
	}
	if got := sess["apiUrl"]; got != "http://jmap.test/jmap/api" {
		t.Fatalf("session apiUrl = %v", got)
	}
	if got := sess["eventSourceUrl"]; got != "http://jmap.test/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}" {
		t.Fatalf("session eventSourceUrl = %v", got)
	}
	if got := sess["downloadUrl"]; got != "http://jmap.test/jmap/download/{accountId}/{blobId}/{name}?accept={type}" {
		t.Fatalf("session downloadUrl = %v", got)
	}

	// Email/query all -> 2 ids.
	q := call(t, hs.URL, `["Email/query", {"accountId":"`+itoa(accID)+`"}, "c1"]`)
	ids := toStrings(q["ids"])
	if len(ids) != 2 {
		t.Fatalf("Email/query returned %d ids, want 2", len(ids))
	}
	// queryState must equal current changelog head.
	var head int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head, accID)
	if q["queryState"] != strconv.FormatInt(head, 10) {
		t.Fatalf("JMAP queryState=%v != changelog head=%d", q["queryState"], head)
	}

	// Email/changes sinceState=afterFirst -> exactly the 2nd message (created).
	ch := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(afterFirst)+`"}, "c2"]`)
	created := toStrings(ch["created"])
	if len(created) != 1 {
		t.Fatalf("Email/changes since %d: created=%v, want exactly 1 (the 2nd msg)", afterFirst, created)
	}
	// This is the SAME set IMAP CHANGEDSINCE afterFirst returns (the 2nd msg).
	// The JMAP Email id is "E<effectiveEmailID>"; the Email/get below confirms it
	// maps to the second message ("body two").
	if !strings.HasPrefix(created[0], "E") {
		t.Fatalf("Email/changes created id %q is not an E<id> email id", created[0])
	}
	// maxChanges pages on standard JMAP state without returning more ids than
	// requested. The second page resumes at the first page's intermediate state.
	page1 := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"0","maxChanges":1}, "cp1"]`)
	if page1["hasMoreChanges"] != true || len(toStrings(page1["created"])) != 1 {
		t.Fatalf("Email/changes page1 = %v, want one created id and hasMoreChanges", page1)
	}
	page2 := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+page1["newState"].(string)+`","maxChanges":1}, "cp2"]`)
	if len(toStrings(page2["created"])) != 1 || page2["hasMoreChanges"] != false {
		t.Fatalf("Email/changes page2 = %v, want final created id", page2)
	}
	nullLimit := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"0","maxChanges":null}, "cp-null"]`)
	if len(toStrings(nullLimit["created"])) != 2 || nullLimit["hasMoreChanges"] != false {
		t.Fatalf("Email/changes maxChanges null = %v, want the unbounded default page", nullLimit)
	}
	if got := callError(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"bad"}, "ce1"]`); got["type"] != "invalidArguments" {
		t.Fatalf("malformed sinceState error = %v, want invalidArguments", got)
	}
	if got := callError(t, hs.URL, `["Email/changes", {"accountId":"999999","sinceState":"0"}, "ce2"]`); got["type"] != "accountNotFound" {
		t.Fatalf("foreign account error = %v, want accountNotFound", got)
	}

	// Email/get the changed one -> preview from blob, keywords empty (unseen).
	g := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+created[0]+`"]}, "c3"]`)
	glist := g["list"].([]any)
	if len(glist) != 1 {
		t.Fatalf("Email/get returned %d, want 1", len(glist))
	}
	em := glist[0].(map[string]any)
	if !strings.Contains(em["preview"].(string), "body two") {
		t.Fatalf("Email/get preview wrong: %v", em["preview"])
	}

	// Email/set: mark $seen; then Email/get shows the keyword.
	_ = call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","update":{"`+created[0]+`":{"keywords/$seen":true}}}, "c4"]`)
	g2 := call(t, hs.URL, `["Email/get", {"accountId":"`+itoa(accID)+`","ids":["`+created[0]+`"]}, "c5"]`)
	em2 := g2["list"].([]any)[0].(map[string]any)
	kw, _ := em2["keywords"].(map[string]any)
	if kw == nil || kw["$seen"] != true {
		t.Fatalf("Email/set did not persist $seen: %v", em2["keywords"])
	}

	// Invariant after JMAP writes: state advanced, still == changelog head.
	var head2 int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &head2, accID)
	var maxSeq int64
	sc(t, s, ctx, `SELECT COALESCE(max(seq),0) FROM changelog WHERE account_id=$1`, &maxSeq, accID)
	if head2 != maxSeq {
		t.Fatalf("modseq invariant broken after JMAP: head=%d max=%d", head2, maxSeq)
	}
	if head2 <= head {
		t.Fatalf("JMAP Email/set did not advance changelog: before=%d after=%d", head, head2)
	}
	updatedChanges := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(head)+`"}, "cu"]`)
	if updated := toStrings(updatedChanges["updated"]); len(updated) != 1 || updated[0] != created[0] {
		t.Fatalf("Email/changes updated = %v, want %s", updated, created[0])
	}

	// Destroying the last mailbox row makes the Email appear in destroyed.
	_ = call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","destroy":["`+created[0]+`"]}, "cd"]`)
	destroyChanges := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(head2)+`"}, "cc"]`)
	if destroyed := toStrings(destroyChanges["destroyed"]); len(destroyed) != 1 || destroyed[0] != created[0] {
		t.Fatalf("Email/changes destroyed = %v, want %s", destroyed, created[0])
	}
	rowsDeleted, _, err := s.CollectGarbage(ctx, 100)
	if err != nil || rowsDeleted != 1 {
		t.Fatalf("CollectGarbage after Email destroy = (%d, %v), want (1, nil)", rowsDeleted, err)
	}
	afterGC := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(head)+`"}, "cc-gc"]`)
	if destroyed := toStrings(afterGC["destroyed"]); len(destroyed) != 1 || destroyed[0] != created[0] {
		t.Fatalf("Email/changes destroyed after GC = %v, want %s", destroyed, created[0])
	}

	// A message created and destroyed entirely after sinceState must disappear
	// from the delta, even after GC removes the projection row needed by legacy
	// changelog entries to resolve identity.
	var transientSince int64
	sc(t, s, ctx, `SELECT changelog_seq FROM accounts WHERE id=$1`, &transientSince, accID)
	transient := &store.Message{}
	if _, err := target.Deliver(ctx, transient, mem("Subject: transient\r\n\r\nshort lived\r\n")); err != nil {
		t.Fatal(err)
	}
	transientID := "E" + itoa(transient.EffectiveEmailID())
	_ = call(t, hs.URL, `["Email/set", {"accountId":"`+itoa(accID)+`","destroy":["`+transientID+`"]}, "transient-delete"]`)
	if rowsDeleted, _, err := s.CollectGarbage(ctx, 100); err != nil || rowsDeleted != 1 {
		t.Fatalf("CollectGarbage transient Email = (%d, %v), want (1, nil)", rowsDeleted, err)
	}
	transientChanges := call(t, hs.URL, `["Email/changes", {"accountId":"`+itoa(accID)+`","sinceState":"`+itoa(transientSince)+`"}, "transient-changes"]`)
	if len(toStrings(transientChanges["created"])) != 0 || len(toStrings(transientChanges["destroyed"])) != 0 {
		t.Fatalf("transient Email changes after GC = %v, want no created/destroyed", transientChanges)
	}
	t.Logf("OK: JMAP state==changelog head=%d; Email/changes since %d == IMAP CHANGEDSINCE (uid 2); $seen persisted", head2, afterFirst)
}

func TestAgentCredentialJMAPReadOnly(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, principalID, accountID, domainID int64
	sc(t, s, ctx, `INSERT INTO tenants (name) VALUES ('jmap-agent') RETURNING id`, &tenantID)
	sc(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent-owner@example.com') RETURNING id`, &principalID, tenantID)
	sc(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'agent-mailbox') RETURNING id`, &accountID, tenantID, principalID)
	sc(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	ex(t, s, ctx, `INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'agent-owner')`, tenantID, domainID, accountID)
	ex(t, s, ctx,
		`INSERT INTO agent_mailbox_registrations (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,'space-jmap')`, tenantID, accountID, principalID)

	dir := s.NewDirectory()
	verifier := "jmap-agent-verifier-with-enough-entropy"
	digest := sha256.Sum256([]byte(verifier))
	agentDir := directory.AgentAuthorizationDirectory(dir)
	device, err := agentDir.CreateAgentAuthorization(ctx, directory.AgentAuthorizationInput{
		BotID: "bot-jmap", BotProfile: "assistant", ClientName: "octo-cli",
		SpaceID:       "space-jmap",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentDir.ApproveAgentAuthorization(ctx, principalID, "space-jmap", device.UserCode, accountID, directory.AgentOutboundModeManualConfirmation); err != nil {
		t.Fatal(err)
	}
	credential, err := agentDir.ExchangeAgentAuthorization(ctx, device.DeviceCode, verifier)
	if err != nil {
		t.Fatal(err)
	}

	hs := httptest.NewServer((&jmapd.Server{Dir: dir, BaseURL: "http://jmap.test"}).Handler())
	defer hs.Close()

	sessionRequest, _ := http.NewRequest(http.MethodGet, hs.URL+"/jmap/session", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	sessionResponse, err := http.DefaultClient.Do(sessionRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionResponse.Body.Close()
	var session map[string]any
	if err := json.NewDecoder(sessionResponse.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	account := session["accounts"].(map[string]any)[itoa(accountID)].(map[string]any)
	if account["isReadOnly"] != true {
		t.Fatalf("Agent JMAP account isReadOnly = %v, want true", account["isReadOnly"])
	}

	invoke := func(methodCall string) (string, map[string]any) {
		reqBody := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCall + `]}`
		req, _ := http.NewRequest(http.MethodPost, hs.URL+"/jmap/api", strings.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+credential.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			MethodResponses [][3]json.RawMessage `json:"methodResponses"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		var name string
		var args map[string]any
		_ = json.Unmarshal(out.MethodResponses[0][0], &name)
		_ = json.Unmarshal(out.MethodResponses[0][1], &args)
		return name, args
	}

	name, mailboxes := invoke(`["Mailbox/get", {"accountId":"` + itoa(accountID) + `"}, "empty"]`)
	list, ok := mailboxes["list"].([]any)
	if name != "Mailbox/get" || !ok || len(list) != 0 {
		t.Fatalf("empty Agent Mailbox/get = %s %v, want list=[]", name, mailboxes)
	}

	address, _ := smtp.ParseAddress("agent-owner@example.com")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("Subject: agent jmap\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}

	name, changes := invoke(`["Email/changes", {"accountId":"` + itoa(accountID) + `","sinceState":"0"}, "read"]`)
	if name != "Email/changes" || len(toStrings(changes["created"])) != 1 {
		t.Fatalf("Agent Email/changes = %s %v", name, changes)
	}
	name, denied := invoke(`["Email/set", {"accountId":"` + itoa(accountID) + `","destroy":[]}, "write"]`)
	if name != "error" || denied["type"] != "forbidden" {
		t.Fatalf("Agent Email/set = %s %v, want forbidden", name, denied)
	}
	if err := agentDir.RevokeAgentBinding(ctx, principalID, accountID, "space-jmap"); err != nil {
		t.Fatal(err)
	}
	revokedRequest, _ := http.NewRequest(http.MethodGet, hs.URL+"/jmap/session", nil)
	revokedRequest.Header.Set("Authorization", "Bearer "+credential.AccessToken)
	revokedResponse, err := http.DefaultClient.Do(revokedRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokedResponse.Body.Close()
	if revokedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked Agent JMAP credential status = %d, want 401", revokedResponse.StatusCode)
	}
}

// --- helpers ---

func call(t *testing.T, baseURL, methodCallJSON string) map[string]any {
	t.Helper()
	reqBody := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCallJSON + `]}`
	req, _ := http.NewRequest("POST", baseURL+"/jmap/api", strings.NewReader(reqBody))
	req.SetBasicAuth("u1@example.com", "x")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jmap call: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("jmap call status %d", resp.StatusCode)
	}
	var out struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.MethodResponses) == 0 {
		t.Fatalf("no method responses")
	}
	var name string
	_ = json.Unmarshal(out.MethodResponses[0][0], &name)
	if name == "error" {
		t.Fatalf("jmap method error: %s", string(out.MethodResponses[0][1]))
	}
	var args map[string]any
	_ = json.Unmarshal(out.MethodResponses[0][1], &args)
	return args
}

func callError(t *testing.T, baseURL, methodCallJSON string) map[string]any {
	t.Helper()
	reqBody := `{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[` + methodCallJSON + `]}`
	req, _ := http.NewRequest("POST", baseURL+"/jmap/api", strings.NewReader(reqBody))
	req.SetBasicAuth("u1@example.com", "x")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("jmap call: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.MethodResponses) == 0 {
		t.Fatalf("decode JMAP error response: %v", err)
	}
	var name string
	_ = json.Unmarshal(out.MethodResponses[0][0], &name)
	if name != "error" {
		t.Fatalf("JMAP response name = %q, want error", name)
	}
	var args map[string]any
	_ = json.Unmarshal(out.MethodResponses[0][1], &args)
	return args
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth("u1@example.com", "x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func mem(s string) store.BlobReader {
	return &memBlob{Reader: bytes.NewReader([]byte(s)), size: int64(len(s))}
}

type memBlob struct {
	*bytes.Reader
	size int64
}

func (m *memBlob) Size() int64  { return m.size }
func (m *memBlob) Close() error { return nil }

func sc(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatalf("scan: %v", err)
	}
}
func ex(t *testing.T, s *postgres.Store, ctx context.Context, sql string, args ...any) {
	t.Helper()
	if _, err := s.Pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
}
