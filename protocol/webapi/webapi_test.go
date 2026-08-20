package webapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/projection"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
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

func TestConfiguredRequestBodyLimit(t *testing.T) {
	handler := (&webapi.Server{MaxMessageSize: 32}).Handler()
	body := `{"botId":"` + strings.Repeat("x", 40) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/webapi/v0/agent-auth/device", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413; body=%s", recorder.Code, recorder.Body.String())
	}
}

// TestRESTAPI exercises the resource-oriented REST surface (/webapi/v0) end to
// end over real HTTP against a real PostgreSQL: per-account auth (401 without
// credentials), send (202 → outbound queue), list/get/raw, flag via PATCH,
// thread get, suppression PUT/GET/list/DELETE, and message DELETE (204 → 404).
func TestRESTAPI(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, suppressions RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "pw"); err != nil {
		t.Fatal(err)
	}

	// Deliver one message so the message resource has something to operate on.
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, err := dir.ResolveInbound(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: friend@remote.example\r\nTo: u1@example.com\r\nCc: peer@remote.example\r\nSubject: hi\r\nMessage-ID: <orig@remote.example>\r\n\r\nbody here\r\n")); err != nil {
		t.Fatal(err)
	}
	// A second account has its own unread message. Every u1 list assertion below
	// therefore also guards the authenticated account boundary.
	var acc2ID int64
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u2') RETURNING id`, &acc2ID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u2')`, tenantID, domID, acc2ID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u2@example.com')`, tenantID)
	if err := dir.SetPassword(ctx, "u2@example.com", "pw2"); err != nil {
		t.Fatal(err)
	}
	u2Address, _ := smtp.ParseAddress("u2@example.com")
	u2Target, err := dir.ResolveInbound(ctx, u2Address.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u2Target.Deliver(ctx, &store.Message{}, mem("From: private@remote.example\r\nTo: u2@example.com\r\nSubject: private\r\nMessage-ID: <private@remote.example>\r\n\r\naccount two\r\n")); err != nil {
		t.Fatal(err)
	}
	// Existing installations may already have a mailbox named Sent without the
	// special-use role. Sending must upgrade it instead of creating a duplicate.
	scope, _, err := dir.AuthenticatePrincipal(ctx, "u1@example.com", directory.PasswordCredential("pw"))
	if err != nil {
		t.Fatal(err)
	}
	account, err := scope.AccountForAddress(ctx, addr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := account.Tx(ctx, func(tx store.Tx) error {
		_, _, err := account.MailboxEnsure(tx, "Sent", true, store.SpecialUse{}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	srv := &webapi.Server{
		Dir:          dir,
		Submission:   &submit.Submitter{Pool: s.Pool, Blob: bs},
		Suppressions: &deliverability.Suppressions{Pool: s.Pool},
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	// do issues an authenticated request and returns (status, decoded-json).
	do := func(method, path, body string) (int, map[string]any) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, hs.URL+path, rd)
		req.SetBasicAuth("u1@example.com", "pw")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		raw, _ := io.ReadAll(resp.Body)
		if len(bytes.TrimSpace(raw)) > 0 {
			json.Unmarshal(raw, &out)
		}
		if e, ok := out["error"]; ok {
			t.Fatalf("%s %s → %d error: %v", method, path, resp.StatusCode, e)
		}
		return resp.StatusCode, out
	}

	// --- auth: no credentials → 401. ---
	for _, path := range []string{"/webapi/v0/mailboxes", "/webapi/v0/state"} {
		resp, _ := http.Get(hs.URL + path)
		if resp.StatusCode != http.StatusUnauthorized {
			_ = resp.Body.Close()
			t.Fatalf("unauthenticated %s status = %d, want 401", path, resp.StatusCode)
		}
		if path == "/webapi/v0/state" && resp.Header.Get("Cache-Control") != "no-store" {
			_ = resp.Body.Close()
			t.Fatalf("unauthenticated state Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
		}
		_ = resp.Body.Close()
	}

	// --- state: stable, account-scoped change-log token. ---
	stateReq, err := http.NewRequest(http.MethodGet, hs.URL+"/webapi/v0/state", nil)
	if err != nil {
		t.Fatal(err)
	}
	stateReq.SetBasicAuth("u1@example.com", "pw")
	stateResp, err := http.DefaultClient.Do(stateReq)
	if err != nil {
		t.Fatal(err)
	}
	if stateResp.Header.Get("Cache-Control") != "no-store" {
		_ = stateResp.Body.Close()
		t.Fatalf("authenticated state Cache-Control = %q, want no-store", stateResp.Header.Get("Cache-Control"))
	}
	_ = stateResp.Body.Close()

	st, state := do("GET", "/webapi/v0/state", "")
	if st != http.StatusOK {
		t.Fatalf("GET state status = %d, want 200", st)
	}
	initialState, ok := state["state"].(string)
	if !ok || initialState == "" {
		t.Fatalf("state = %v, want non-empty string", state["state"])
	}
	_, sameState := do("GET", "/webapi/v0/state", "")
	if sameState["state"] != initialState {
		t.Fatalf("unchanged state = %v, want %q", sameState["state"], initialState)
	}

	// --- mailboxes: Inbox present. ---
	st, mb := do("GET", "/webapi/v0/mailboxes", "")
	if st != http.StatusOK {
		t.Fatalf("GET mailboxes status = %d, want 200", st)
	}
	if !hasMailbox(mb["mailboxes"], "Inbox") {
		t.Fatalf("mailboxes missing Inbox: %v", mb["mailboxes"])
	}
	_, identity := do("GET", "/webapi/v0/identity", "")
	if identity["address"] != "u1@example.com" {
		t.Fatalf("identity address = %v, want u1@example.com", identity["address"])
	}

	// --- addresses: list primary, create and delete an account-scoped alias. ---
	st, addressList := do("GET", "/webapi/v0/addresses", "")
	if st != http.StatusOK {
		t.Fatalf("GET addresses status = %d, want 200", st)
	}
	addresses, _ := addressList["addresses"].([]any)
	if len(addresses) != 1 || addresses[0].(map[string]any)["primary"] != true {
		t.Fatalf("addresses = %v, want one primary address", addresses)
	}
	primaryID := addresses[0].(map[string]any)["id"].(string)
	st, alias := do("POST", "/webapi/v0/addresses", `{"localpart":"agent-alerts"}`)
	if st != http.StatusCreated || alias["address"] != "agent-alerts@example.com" || alias["primary"] != false {
		t.Fatalf("created alias = status %d body %v", st, alias)
	}
	aliasID := alias["id"].(string)
	aliasAddress, _ := smtp.ParseAddress("agent-alerts@example.com")
	aliasTarget, err := dir.ResolveInbound(ctx, aliasAddress.Path())
	if err != nil || !aliasTarget.IsAlias() || aliasTarget.AccountID() != account.ID() {
		t.Fatalf("alias resolution = target %#v err %v", aliasTarget, err)
	}
	st, _ = do("DELETE", "/webapi/v0/addresses/"+aliasID, "")
	if st != http.StatusNoContent {
		t.Fatalf("DELETE alias status = %d, want 204", st)
	}
	if _, err := dir.ResolveInbound(ctx, aliasAddress.Path()); err == nil {
		t.Fatal("deleted alias still resolves inbound")
	}
	request, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/addresses/"+primaryID, nil)
	request.SetBasicAuth("u1@example.com", "pw")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		response.Body.Close()
		t.Fatalf("DELETE primary address status = %d, want 400", response.StatusCode)
	}
	response.Body.Close()

	// --- list: the delivered message shows up; capture its id. ---
	st, lst := do("GET", "/webapi/v0/messages", "")
	if st != http.StatusOK {
		t.Fatalf("GET messages status = %d, want 200", st)
	}
	msgs, _ := lst["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("list returned %d messages, want 1", len(msgs))
	}
	m0 := msgs[0].(map[string]any)
	id, _ := m0["id"].(string)
	if id == "" || id[0] != 'E' {
		t.Fatalf("message id = %q, want E<n>", id)
	}
	if m0["unread"] != true {
		t.Fatalf("new message should be unread: %v", m0)
	}
	// The projection hasn't folded this just-delivered row, so the summary comes
	// from the hybrid on-the-fly fallback — it must still be correct (H13 PR2).
	if m0["subject"] != "hi" {
		t.Fatalf("list subject = %v, want 'hi' (hybrid fallback for unfolded row)", m0["subject"])
	}
	// The second account cannot read, flag, or delete u1's message even when it
	// knows the globally formatted Email id.
	for _, attempt := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/webapi/v0/messages/" + id, ""},
		{http.MethodPatch, "/webapi/v0/messages/" + id, `{"addKeywords":["\\Seen"]}`},
		{http.MethodDelete, "/webapi/v0/messages/" + id, ""},
	} {
		var body io.Reader
		if attempt.body != "" {
			body = strings.NewReader(attempt.body)
		}
		request, _ := http.NewRequest(attempt.method, hs.URL+attempt.path, body)
		request.SetBasicAuth("u2@example.com", "pw2")
		if attempt.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("cross-account %s %s status = %d, want 404", attempt.method, attempt.path, response.StatusCode)
		}
	}
	// Add a second unread message to prove filtering happens before Count, Limit,
	// and Offset. The other account's unread message must remain invisible.
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: second@remote.example\r\nTo: u1@example.com\r\nSubject: second\r\nMessage-ID: <second@remote.example>\r\n\r\nsecond body\r\n")); err != nil {
		t.Fatal(err)
	}
	_, unreadPage1 := do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=true&limit=1&offset=0", "")
	_, unreadPage2 := do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=true&limit=1&offset=1", "")
	if unreadPage1["total"] != float64(2) || unreadPage2["total"] != float64(2) {
		t.Fatalf("unread page totals = %v / %v, want 2 account-scoped messages", unreadPage1, unreadPage2)
	}
	page1Messages := unreadPage1["messages"].([]any)
	page2Messages := unreadPage2["messages"].([]any)
	if len(page1Messages) != 1 || len(page2Messages) != 1 || page1Messages[0].(map[string]any)["id"] == page2Messages[0].(map[string]any)["id"] {
		t.Fatalf("unread pages are not distinct single-message pages: %v / %v", unreadPage1, unreadPage2)
	}
	secondID := page1Messages[0].(map[string]any)["id"].(string)
	if secondID == id {
		secondID = page2Messages[0].(map[string]any)["id"].(string)
	}
	deleteSecond, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/messages/"+secondID, nil)
	deleteSecond.SetBasicAuth("u1@example.com", "pw")
	deleteSecondResponse, err := http.DefaultClient.Do(deleteSecond)
	if err != nil {
		t.Fatal(err)
	}
	if deleteSecondResponse.StatusCode != http.StatusNoContent {
		deleteSecondResponse.Body.Close()
		t.Fatalf("delete paging fixture status = %d, want 204", deleteSecondResponse.StatusCode)
	}
	deleteSecondResponse.Body.Close()

	// Optional unread filtering is applied before counting and paging. Omitting
	// the parameter preserves the existing all-message behavior.
	st, unreadList := do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=true", "")
	if st != http.StatusOK || unreadList["total"] != float64(1) || len(unreadList["messages"].([]any)) != 1 {
		t.Fatalf("unread=true list = status %d body %v, want one unread Inbox message", st, unreadList)
	}
	st, readList := do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=false", "")
	if st != http.StatusOK || readList["total"] != float64(0) || len(readList["messages"].([]any)) != 0 {
		t.Fatalf("unread=false list = status %d body %v, want no read Inbox messages", st, readList)
	}
	invalidUnread, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages?unread=yes", nil)
	invalidUnread.SetBasicAuth("u1@example.com", "pw")
	invalidUnreadResponse, err := http.DefaultClient.Do(invalidUnread)
	if err != nil {
		t.Fatal(err)
	}
	if invalidUnreadResponse.StatusCode != http.StatusBadRequest {
		invalidUnreadResponse.Body.Close()
		t.Fatalf("invalid unread status = %d, want 400", invalidUnreadResponse.StatusCode)
	}
	invalidUnreadResponse.Body.Close()

	// --- get: bodies + subject. ---
	st, get := do("GET", "/webapi/v0/messages/"+id, "")
	if st != http.StatusOK {
		t.Fatalf("GET message status = %d, want 200", st)
	}
	if get["subject"] != "hi" || !strings.Contains(toString(get["bodyText"]), "body here") {
		t.Fatalf("GET message unexpected: subject=%v body=%v", get["subject"], get["bodyText"])
	}

	// --- raw: message/rfc822 bytes. ---
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+id+"/raw", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "message/rfc822" {
			t.Fatalf("raw content-type = %q, want message/rfc822", ct)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(raw, []byte("body here")) {
			t.Fatalf("raw did not return body: %.60q", raw)
		}
	}

	// --- send: 202 + submissionIds/messageId, one queue row and one Sent copy. ---
	var sentID string
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/messages",
			strings.NewReader(`{"to":["dst@remote.example"],"subject":"hello","text":"greetings","attachments":[{"filename":"report.txt","contentType":"text/plain","content":"YXR0YWNobWVudCBib2R5"}]}`))
		req.SetBasicAuth("u1@example.com", "pw")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST messages status = %d, want 202", resp.StatusCode)
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if ids, _ := out["submissionIds"].([]any); len(ids) != 1 {
			t.Fatalf("send submissionIds = %v, want 1", out["submissionIds"])
		}
		if out["senderAddress"] != "u1@example.com" {
			t.Fatalf("send senderAddress = %v, want u1@example.com", out["senderAddress"])
		}
		sentID, _ = out["messageId"].(string)
		if sentID == "" {
			t.Fatalf("send messageId = %v, want Sent message id", out["messageId"])
		}
	}
	var qn int
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 1 {
		t.Fatalf("queue rows = %d, want 1 after send", qn)
	}
	var sentCopies int
	scan(t, s, ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb
		 ON mb.account_id=m.account_id AND mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND mb.name='Sent' AND mb.su_sent AND m.f_seen AND NOT m.expunged`,
		&sentCopies, accID)
	if sentCopies != 1 {
		t.Fatalf("Sent copies = %d, want 1 read copy", sentCopies)
	}
	_, mailboxesAfterSend := do("GET", "/webapi/v0/mailboxes", "")
	var sentRole bool
	for _, item := range mailboxesAfterSend["mailboxes"].([]any) {
		mailbox := item.(map[string]any)
		if mailbox["name"] == "Sent" && mailbox["role"] == "sent" {
			sentRole = true
		}
	}
	if !sentRole {
		t.Fatalf("Sent mailbox did not expose role=sent: %v", mailboxesAfterSend["mailboxes"])
	}
	_, sentDetail := do("GET", "/webapi/v0/messages/"+sentID, "")
	attachments, _ := sentDetail["attachments"].([]any)
	if len(attachments) != 1 {
		t.Fatalf("Sent attachment metadata = %v, want one attachment", sentDetail["attachments"])
	}
	attachmentInfo := attachments[0].(map[string]any)
	partID, _ := attachmentInfo["partId"].(string)
	if partID == "" || attachmentInfo["filename"] != "report.txt" || attachmentInfo["contentType"] != "text/plain" {
		t.Fatalf("attachment metadata = %v", attachmentInfo)
	}
	attachmentRequest, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+sentID+"/attachments/"+partID, nil)
	attachmentRequest.SetBasicAuth("u1@example.com", "pw")
	attachmentResponse, err := http.DefaultClient.Do(attachmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	attachmentBody, _ := io.ReadAll(attachmentResponse.Body)
	attachmentResponse.Body.Close()
	if attachmentResponse.StatusCode != http.StatusOK || string(attachmentBody) != "attachment body" ||
		attachmentResponse.Header.Get("X-Content-Type-Options") != "nosniff" ||
		(attachmentResponse.ContentLength >= 0 && attachmentResponse.ContentLength != int64(len(attachmentBody))) {
		t.Fatalf("attachment download = status %d body %q headers %v", attachmentResponse.StatusCode, attachmentBody, attachmentResponse.Header)
	}
	foreignAttachmentRequest, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+sentID+"/attachments/"+partID, nil)
	foreignAttachmentRequest.SetBasicAuth("u2@example.com", "pw2")
	foreignAttachmentResponse, err := http.DefaultClient.Do(foreignAttachmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	foreignAttachmentResponse.Body.Close()
	if foreignAttachmentResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account attachment status = %d, want 404", foreignAttachmentResponse.StatusCode)
	}
	_, delivery := do("GET", "/webapi/v0/messages/"+sentID+"/delivery", "")
	if delivery["status"] != "sending" || delivery["total"] != float64(1) {
		t.Fatalf("initial delivery = %v, want sending for one recipient", delivery)
	}

	// --- reply: derives recipient + threading, enqueues. ---
	{
		req, _ := http.NewRequest("POST", hs.URL+"/webapi/v0/messages/"+id+"/reply",
			strings.NewReader(`{"text":"thanks"}`))
		req.SetBasicAuth("u1@example.com", "pw")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("POST reply status = %d, want 202", resp.StatusCode)
		}
		resp.Body.Close()
	}
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 2 {
		t.Fatalf("queue rows = %d, want 2 after reply", qn)
	}
	_, replyAll := do("POST", "/webapi/v0/messages/"+id+"/reply-all", `{"text":"thanks all"}`)
	replyAllID, _ := replyAll["messageId"].(string)
	if replyAllID == "" {
		t.Fatalf("reply-all messageId = %v", replyAll["messageId"])
	}
	_, forward := do("POST", "/webapi/v0/messages/"+id+"/forward", `{"to":["forward@remote.example"],"text":"FYI"}`)
	forwardID, _ := forward["messageId"].(string)
	if forwardID == "" {
		t.Fatalf("forward messageId = %v", forward["messageId"])
	}
	scan(t, s, ctx, `SELECT count(*) FROM queue`, &qn)
	if qn != 5 {
		t.Fatalf("queue rows = %d, want 5 after send+reply+reply-all+forward", qn)
	}
	var peerRecipients, friendRecipients, forwardRecipients int
	scan(t, s, ctx, `SELECT count(*) FROM queue WHERE rcpt_to='peer@remote.example'`, &peerRecipients)
	scan(t, s, ctx, `SELECT count(*) FROM queue WHERE rcpt_to='friend@remote.example'`, &friendRecipients)
	scan(t, s, ctx, `SELECT count(*) FROM queue WHERE rcpt_to='forward@remote.example'`, &forwardRecipients)
	if peerRecipients != 1 || friendRecipients != 2 || forwardRecipients != 1 {
		t.Fatalf("reply-all/forward recipients peer=%d friend=%d forward=%d", peerRecipients, friendRecipients, forwardRecipients)
	}
	scan(t, s, ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb
		 ON mb.account_id=m.account_id AND mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND mb.name='Sent' AND NOT m.expunged`,
		&sentCopies, accID)
	if sentCopies != 4 {
		t.Fatalf("Sent copies = %d, want 4 after send+reply+reply-all+forward", sentCopies)
	}
	for messageID, wantHeader := range map[string]string{
		replyAllID: "In-Reply-To: <orig@remote.example>",
		forwardID:  "Subject: Fwd: hi",
	} {
		request, _ := http.NewRequest(http.MethodGet, hs.URL+"/webapi/v0/messages/"+messageID+"/raw", nil)
		request.SetBasicAuth("u1@example.com", "pw")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte(wantHeader)) {
			t.Fatalf("message %s raw missing %q: %.200q", messageID, wantHeader, raw)
		}
		if messageID == forwardID {
			for _, header := range []string{
				"From: u1@example.com", "X-Octo-Original-From: friend@remote.example", "X-Octo-Sent-By: u1@example.com",
			} {
				if !bytes.Contains(raw, []byte(header)) {
					t.Fatalf("manual forward raw missing %q: %.500q", header, raw)
				}
			}
			if bytes.Contains(bytes.ToLower(raw), []byte("reply-to:")) {
				t.Fatalf("manual forward unexpectedly redirects replies: %.500q", raw)
			}
		}
		if messageID == replyAllID && !bytes.Contains(raw, []byte("References: <orig@remote.example>")) {
			t.Fatalf("reply-all raw missing References chain: %.200q", raw)
		}
	}
	worker := &queue.Worker{
		Pool: s.Pool, NodeID: "webapi-test", Batch: 10,
		Deliver: func(context.Context, queue.Msg) error { return nil },
	}
	if processed, err := worker.RunOnce(ctx); err != nil || processed != 5 {
		t.Fatalf("delivery worker processed=%d err=%v, want 5 successful sends", processed, err)
	}
	_, delivered := do("GET", "/webapi/v0/messages/"+sentID+"/delivery", "")
	if delivered["status"] != "delivered" || delivered["delivered"] != float64(1) {
		t.Fatalf("final delivery = %v, want delivered", delivered)
	}

	// --- multi-recipient delivery: one accepted and one rejected. ---
	_, partialSend := do("POST", "/webapi/v0/messages",
		`{"to":["ok@remote.example","reject@remote.example"],"subject":"mixed","text":"status"}`)
	partialID, _ := partialSend["messageId"].(string)
	mixedWorker := &queue.Worker{
		Pool: s.Pool, NodeID: "webapi-mixed-test", Batch: 10,
		Deliver: func(_ context.Context, message queue.Msg) error {
			if message.RcptTo == "reject@remote.example" {
				return webapiPermanentError{}
			}
			return nil
		},
	}
	if processed, err := mixedWorker.RunOnce(ctx); err != nil || processed != 2 {
		t.Fatalf("mixed delivery processed=%d err=%v, want 2", processed, err)
	}
	_, partial := do("GET", "/webapi/v0/messages/"+partialID+"/delivery", "")
	if partial["status"] != "partially_delivered" || partial["delivered"] != float64(1) || partial["total"] != float64(2) {
		t.Fatalf("mixed delivery = %v, want partially_delivered 1/2", partial)
	}
	if recipients, _ := partial["recipients"].([]any); len(recipients) != 2 {
		t.Fatalf("mixed recipients = %v, want two results", partial["recipients"])
	}
	var rejectedLive int
	scan(t, s, ctx, `SELECT count(*) FROM queue WHERE rcpt_to='reject@remote.example'`, &rejectedLive)
	if rejectedLive != 0 {
		t.Fatalf("SMTP 550 recipient remains queued: %d", rejectedLive)
	}

	// --- drafts: create/list/send/delete through the WebAPI surface. ---
	st, createdDraft := do("POST", "/webapi/v0/drafts", `{"to":["draft@remote.example"],"subject":"draft subject","text":"draft body"}`)
	if st != http.StatusCreated {
		t.Fatalf("create draft status = %d, want 201", st)
	}
	draftID, _ := createdDraft["id"].(string)
	_, draftList := do("GET", "/webapi/v0/drafts", "")
	if drafts, _ := draftList["drafts"].([]any); len(drafts) != 1 || drafts[0].(map[string]any)["id"] != draftID {
		t.Fatalf("draft list = %v, want %s", draftList, draftID)
	}
	foreignDraftDelete, _ := http.NewRequest(http.MethodDelete, hs.URL+"/webapi/v0/drafts/"+draftID, nil)
	foreignDraftDelete.SetBasicAuth("u2@example.com", "pw2")
	foreignDraftResponse, err := http.DefaultClient.Do(foreignDraftDelete)
	if err != nil {
		t.Fatal(err)
	}
	foreignDraftResponse.Body.Close()
	if foreignDraftResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account draft delete status = %d, want 404", foreignDraftResponse.StatusCode)
	}
	st, updatedDraft := do("PATCH", "/webapi/v0/drafts/"+draftID, `{"to":["draft@remote.example"],"subject":"updated draft subject","text":"updated draft body"}`)
	if st != http.StatusOK || updatedDraft["id"] == "" || updatedDraft["id"] == draftID {
		t.Fatalf("update draft = status %d body %v", st, updatedDraft)
	}
	draftID = updatedDraft["id"].(string)
	st, draftDetail := do("GET", "/webapi/v0/messages/"+draftID, "")
	if st != http.StatusOK || draftDetail["subject"] != "updated draft subject" || draftDetail["bodyText"] != "updated draft body\r\n" {
		t.Fatalf("updated draft detail = status %d body %v", st, draftDetail)
	}
	st, sentDraft := do("POST", "/webapi/v0/drafts/"+draftID+"/send", "")
	if st != http.StatusAccepted || sentDraft["messageId"] == "" {
		t.Fatalf("send draft = status %d body %v", st, sentDraft)
	}
	_, draftList = do("GET", "/webapi/v0/drafts", "")
	if drafts, _ := draftList["drafts"].([]any); len(drafts) != 0 {
		t.Fatalf("draft list after delete = %v, want empty", draftList)
	}

	// A durable account-scoped claim prevents two nodes from submitting the
	// same immutable Draft concurrently. Both callers may observe the same
	// accepted result, but only one queue submission may be created.
	st, concurrentDraft := do("POST", "/webapi/v0/drafts", `{"to":["concurrent@remote.example"],"subject":"one send","text":"body"}`)
	if st != http.StatusCreated {
		t.Fatalf("create concurrent Draft = %d %#v", st, concurrentDraft)
	}
	concurrentDraftID := concurrentDraft["id"].(string)
	startConcurrent := make(chan struct{})
	statuses := make(chan int, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			<-startConcurrent
			req, err := http.NewRequest(http.MethodPost, hs.URL+"/webapi/v0/drafts/"+concurrentDraftID+"/send", nil)
			if err != nil {
				errors <- err
				return
			}
			req.SetBasicAuth("u1@example.com", "pw")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errors <- err
				return
			}
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	close(startConcurrent)
	accepted := 0
	for range 2 {
		select {
		case err := <-errors:
			t.Fatal(err)
		case status := <-statuses:
			if status == http.StatusAccepted {
				accepted++
			} else if status != http.StatusConflict && status != http.StatusNotFound {
				t.Fatalf("concurrent Draft send status = %d", status)
			}
		}
	}
	if accepted == 0 {
		t.Fatal("concurrent Draft send had no accepted result")
	}
	var concurrentQueueRows int
	scan(t, s, ctx, `SELECT count(*) FROM queue WHERE account_id=$1 AND rcpt_to='concurrent@remote.example'`, &concurrentQueueRows, accID)
	if concurrentQueueRows != 1 {
		t.Fatalf("concurrent Draft queue rows = %d, want 1", concurrentQueueRows)
	}

	// --- flag via PATCH: add \Seen, becomes read. ---
	do("PATCH", "/webapi/v0/messages/"+id, `{"addKeywords":["\\Seen"]}`)
	_, get2 := do("GET", "/webapi/v0/messages/"+id, "")
	if get2["unread"] != false {
		t.Fatalf("after \\Seen PATCH, unread = %v, want false", get2["unread"])
	}
	_, readList = do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=false", "")
	if readList["total"] != float64(1) || len(readList["messages"].([]any)) != 1 {
		t.Fatalf("read Inbox list after \\Seen = %v, want one message", readList)
	}
	_, unreadList = do("GET", "/webapi/v0/messages?mailbox=Inbox&unread=true", "")
	if unreadList["total"] != float64(0) || len(unreadList["messages"].([]any)) != 0 {
		t.Fatalf("unread Inbox list after \\Seen = %v, want no messages", unreadList)
	}
	_, changedState := do("GET", "/webapi/v0/state", "")
	before, beforeErr := strconv.ParseInt(initialState, 10, 64)
	after, afterErr := strconv.ParseInt(changedState["state"].(string), 10, 64)
	if beforeErr != nil || afterErr != nil || after <= before {
		t.Fatalf("state after mutations = %v, want numeric state greater than %q", changedState["state"], initialState)
	}

	// --- thread get: the message belongs to a thread. ---
	if tid, _ := get2["threadId"].(string); tid != "" {
		st, th := do("GET", "/webapi/v0/threads/"+tid, "")
		if st != http.StatusOK {
			t.Fatalf("GET thread status = %d, want 200", st)
		}
		if tmsgs, _ := th["messages"].([]any); len(tmsgs) < 1 {
			t.Fatalf("thread returned no messages: %v", th)
		}
	}

	// --- suppressions: PUT (idempotent) / GET / list / DELETE. ---
	st, _ = do("PUT", "/webapi/v0/suppressions/bad@remote.example", `{"reason":"bounce"}`)
	if st != http.StatusOK {
		t.Fatalf("PUT suppression status = %d, want 200", st)
	}
	st, _ = do("GET", "/webapi/v0/suppressions/bad@remote.example", "")
	if st != http.StatusOK {
		t.Fatalf("GET suppression presence status = %d, want 200", st)
	}
	_, sl := do("GET", "/webapi/v0/suppressions", "")
	if sups, _ := sl["suppressions"].([]any); len(sups) != 1 || sups[0] != "bad@remote.example" {
		t.Fatalf("suppression list = %v, want [bad@remote.example]", sl["suppressions"])
	}
	{
		req, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/suppressions/bad@remote.example", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE suppression status = %d, want 204", resp.StatusCode)
		}
		resp.Body.Close()
	}
	// Absent now → 404.
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/suppressions/bad@remote.example", nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET removed suppression status = %d, want 404", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// --- delete message: 204, then GET → 404. ---
	{
		req, _ := http.NewRequest("DELETE", hs.URL+"/webapi/v0/messages/"+id, nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("DELETE message status = %d, want 204", resp.StatusCode)
		}
		resp.Body.Close()
	}
	{
		req, _ := http.NewRequest("GET", hs.URL+"/webapi/v0/messages/"+id, nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET deleted message status = %d, want 404", resp.StatusCode)
		}
		resp.Body.Close()
	}

	t.Logf("OK: REST auth + mailboxes + list/get/raw + send/reply(enqueue) + PATCH flag + thread + suppressions + delete over real HTTP")
}

type webapiPermanentError struct{}

func (webapiPermanentError) Error() string             { return "550 recipient rejected" }
func (webapiPermanentError) SMTPResult() (int, string) { return 550, "5.1.1" }
func (webapiPermanentError) Permanent() bool           { return true }

func scan(t *testing.T, s *postgres.Store, ctx context.Context, sql string, dst any, args ...any) {
	t.Helper()
	if err := s.Pool.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
		t.Fatal(err)
	}
}

func hasMailbox(v any, name string) bool {
	list, _ := v.([]any)
	for _, x := range list {
		if mb, ok := x.(map[string]any); ok && mb["name"] == name {
			return true
		}
	}
	return false
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func mem(s string) store.BlobReader {
	return &memBlob{Reader: bytes.NewReader([]byte(s)), n: int64(len(s))}
}

type memBlob struct {
	*bytes.Reader
	n int64
}

func (m *memBlob) Close() error { return nil }
func (m *memBlob) Size() int64  { return m.n }

// TestListPagingAndFold proves the H13 PR2 list path: with the projection folded,
// summaries come from the columns (no body parse), total is accurate across many
// messages, and deep paging (offset past the first page) returns the right
// window newest-first.
func TestListPagingAndFold(t *testing.T) {
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
	if _, err := s.Pool.Exec(ctx, `TRUNCATE messages, mailboxes, changelog, addresses, accounts, domains, principals, tenants, quota_counters, blobs, queue, suppressions, projection_cursor, thread_refs RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	var tenantID, accID, domID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('t') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, name) VALUES ($1,'u1') RETURNING id`, &accID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domID, tenantID)
	s.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'u1')`, tenantID, domID, accID)
	s.Pool.Exec(ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'u1@example.com')`, tenantID)
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "u1@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	addr, _ := smtp.ParseAddress("u1@example.com")
	target, _ := dir.ResolveInbound(ctx, addr.Path())
	const n = 25
	for i := 0; i < n; i++ {
		raw := "From: s" + itoa(i) + "@remote.example\r\nTo: u1@example.com\r\nSubject: msg" + itoa(i) + "\r\n\r\nbody" + itoa(i) + "\r\n"
		if _, err := target.Deliver(ctx, &store.Message{}, mem(raw)); err != nil {
			t.Fatal(err)
		}
	}
	// One message with display-named sender + two named recipients, to prove the
	// display columns hold bare addresses (correct count) not name-shattered tokens.
	named := "From: Alice Smith <alice@remote.example>\r\nTo: Bob Jones <bob@x.example>, Carol <carol@y.example>\r\nSubject: msg25\r\n\r\nbody25\r\n"
	if _, err := target.Deliver(ctx, &store.Message{}, mem(named)); err != nil {
		t.Fatal(err)
	}
	// Fold so summaries read from columns.
	tw := &projection.ThreadWorker{Pool: s.Pool, Blob: bs, Batch: 100}
	if err := tw.DrainAccount(ctx, tenantID, accID); err != nil {
		t.Fatal(err)
	}

	srv := &webapi.Server{Dir: dir, Submission: &submit.Submitter{Pool: s.Pool, Blob: bs}, Suppressions: &deliverability.Suppressions{Pool: s.Pool}}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	get := func(path string) map[string]any {
		req, _ := http.NewRequest("GET", hs.URL+path, nil)
		req.SetBasicAuth("u1@example.com", "pw")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// Page 1: limit 10 → 10 messages, accurate total (not capped).
	total := n + 1 // the 25 plain messages + the display-named one
	p1 := get("/webapi/v0/messages?limit=10&offset=0")
	if int(p1["total"].(float64)) != total {
		t.Fatalf("total = %v, want %d", p1["total"], total)
	}
	m1, _ := p1["messages"].([]any)
	if len(m1) != 10 {
		t.Fatalf("page1 = %d messages, want 10", len(m1))
	}
	// Newest first: the display-named msg25 is first (delivered last). Its display
	// fields must be bare addresses, NOT name-shattered: from="alice@…" (no name),
	// to=["bob@x.example","carol@y.example"] (2 recipients, not 4 name tokens).
	top := m1[0].(map[string]any)
	if top["subject"] != "msg25" {
		t.Fatalf("page1[0] subject = %v, want msg25 (newest-first)", top["subject"])
	}
	if top["from"] != "alice@remote.example" {
		t.Fatalf("display from = %v, want bare 'alice@remote.example' (no display-name prefix)", top["from"])
	}
	toList, _ := top["to"].([]any)
	if len(toList) != 2 || toList[0] != "bob@x.example" || toList[1] != "carol@y.example" {
		t.Fatalf("display to = %v, want [bob@x.example carol@y.example] (not name-shattered)", toList)
	}
	// Deep page: offset 21, limit 10 → last 5 (msg4..msg0).
	p3 := get("/webapi/v0/messages?limit=10&offset=21")
	m3, _ := p3["messages"].([]any)
	if len(m3) != 5 {
		t.Fatalf("offset=21 page = %d messages, want 5 (deep paging)", len(m3))
	}
	if s0 := m3[0].(map[string]any)["subject"]; s0 != "msg4" {
		t.Fatalf("offset=21 page[0] subject = %v, want msg4", s0)
	}
	// limit clamp: ?limit=0 and ?limit=<huge> must NOT return the whole account
	// uncapped — they clamp to maxListLimit (1000), so all `total` rows return
	// (bounded), never more than the cap.
	for _, path := range []string{"/webapi/v0/messages?limit=0", "/webapi/v0/messages?limit=999999999"} {
		p := get(path)
		mm, _ := p["messages"].([]any)
		if len(mm) != total {
			t.Fatalf("%s = %d messages, want %d (clamped, all returned)", path, len(mm), total)
		}
		if lim := int(p["limit"].(float64)); lim != 1000 {
			t.Fatalf("%s echoed limit=%d, want 1000 (clamped)", path, lim)
		}
	}
	t.Logf("OK: accurate total(%d), newest-first, deep paging, bare-address display, limit clamp", total)
}

func itoa(i int) string { return strconv.Itoa(i) }
