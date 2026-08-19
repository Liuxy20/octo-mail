package webapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestAgentOutboundPolicyCreatesOneDurableDraft(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer db.Close()
	if _, err := db.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, ownerPrincipalID, ownerAccountID, domainID int64
	scan(t, db, ctx, `INSERT INTO tenants (name) VALUES ('outbound-policy') RETURNING id`, &tenantID)
	scan(t, db, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@example.com') RETURNING id`, &ownerPrincipalID, tenantID)
	scan(t, db, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'owner') RETURNING id`, &ownerAccountID, tenantID, ownerPrincipalID)
	scan(t, db, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'owner')`,
		tenantID, domainID, ownerAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','octo-owner','space-a',$1,$2,$3)`,
		tenantID, ownerPrincipalID, ownerAccountID); err != nil {
		t.Fatal(err)
	}
	dir := db.NewDirectory()
	if err := dir.SetPassword(ctx, "owner@example.com", "owner-pw"); err != nil {
		t.Fatal(err)
	}

	gatewaySecret := []byte(strings.Repeat("g", 32))
	server := &webapi.Server{
		Dir: dir, Submission: &submit.Submitter{Pool: db.Pool, Blob: bs},
		OutboundPolicy: outboundpolicy.NewKeywordEvaluator([]string{"payment"}), GatewaySecret: gatewaySecret,
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	type requestAuth struct {
		basicUser, basicPassword string
		bearer, confirmation     string
		automation               bool
		idempotencyKey           string
		gatewaySubject, spaceID  string
	}
	do := func(method, path string, body any, auth requestAuth) (int, map[string]any) {
		var reader io.Reader
		var requestBody []byte
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			requestBody = encoded
			reader = bytes.NewReader(requestBody)
		}
		req, err := http.NewRequest(method, httpServer.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if auth.gatewaySubject != "" {
			token, err := gatewayassert.Sign(gatewaySecret, "octo-server", auth.gatewaySubject, auth.spaceID, method, path, requestBody, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
		} else if auth.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+auth.bearer)
		} else if auth.basicUser != "" {
			req.SetBasicAuth(auth.basicUser, auth.basicPassword)
		}
		if auth.confirmation != "" {
			req.Header.Set("X-Octo-Confirmation", auth.confirmation)
		}
		if auth.automation {
			req.Header.Set("X-Octo-Automation", "auto-reply")
		}
		if auth.idempotencyKey != "" {
			req.Header.Set("X-Octo-Idempotency-Key", auth.idempotencyKey)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		result := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode %s %s: %v (%s)", method, path, err, raw)
			}
		}
		return response.StatusCode, result
	}

	ownerAuth := requestAuth{gatewaySubject: "octo-owner", spaceID: "space-a"}
	status, mailbox := do(http.MethodPost, "/webapi/v0/agent-mailboxes", map[string]any{"localpart": "support"}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create Agent mailbox = %d %#v", status, mailbox)
	}
	mailboxID := mailbox["id"].(string)
	mailAccountID, err := strconv.ParseInt(mailboxID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	// The browser path normally reaches this mailbox through the authenticated
	// owner mailbox-context gateway. Give the mailbox address a local password in
	// this isolated direct-WebAPI test so it can exercise the same human handler.
	if err := dir.SetPassword(ctx, "support@example.com", "support-owner-pw"); err != nil {
		t.Fatal(err)
	}

	verifier := "outbound-policy-verifier-with-enough-entropy"
	verifierDigest := sha256.Sum256([]byte(verifier))
	status, device := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
		"botId": "bot-policy", "botProfile": "agent-policy", "clientName": "policy-test",
		"spaceId":       "space-a",
		"codeChallenge": base64.RawURLEncoding.EncodeToString(verifierDigest[:]),
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("create device request = %d %#v", status, device)
	}
	status, approved := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+device["userCode"].(string)+"/approve", map[string]any{
		"mailboxId": mailboxID, "outboundMode": "automatic_send",
	}, ownerAuth)
	if status != http.StatusOK || approved["approved"] != true {
		t.Fatalf("approve device = %d %#v", status, approved)
	}
	status, exchanged := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": device["deviceCode"], "codeVerifier": verifier,
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("exchange device = %d %#v", status, exchanged)
	}
	agentToken := exchanged["accessToken"].(string)

	matchedBody := map[string]any{
		"to": []string{"recipient@example.net"}, "bcc": []string{"audit@example.net"},
		"subject": "Payment plan", "text": "Please review this payment.",
	}
	status, reviewed := do(http.MethodPost, "/webapi/v0/agent-send-intents", matchedBody, requestAuth{
		bearer: agentToken, idempotencyKey: "tool-call-policy-001",
	})
	if status != http.StatusConflict || reviewed["error"].(map[string]any)["code"] != "outbound_review_required" {
		t.Fatalf("review response = %d %#v", status, reviewed)
	}
	policy := reviewed["policy"].(map[string]any)
	draftID := policy["draftId"].(string)
	if policy["status"] != "pending_confirmation" || draftID == "" {
		t.Fatalf("policy projection = %#v", policy)
	}

	status, duplicate := do(http.MethodPost, "/webapi/v0/agent-send-intents", matchedBody, requestAuth{
		bearer: agentToken, idempotencyKey: "tool-call-policy-001",
	})
	if status != http.StatusConflict || duplicate["policy"].(map[string]any)["draftId"] != draftID {
		t.Fatalf("duplicate review response = %d %#v", status, duplicate)
	}

	var draftMessages, policyRows, sentMessages, queueRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_draft`, mailAccountID).Scan(&draftMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_policy_drafts WHERE account_id=$1`, mailAccountID).Scan(&policyRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, mailAccountID).Scan(&sentMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE account_id=$1`, mailAccountID).Scan(&queueRows); err != nil {
		t.Fatal(err)
	}
	if draftMessages != 1 || policyRows != 1 || sentMessages != 0 || queueRows != 0 {
		t.Fatalf("side effects drafts=%d policy=%d sent=%d queue=%d, want 1/1/0/0", draftMessages, policyRows, sentMessages, queueRows)
	}

	status, listed := do(http.MethodGet, "/webapi/v0/drafts", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK {
		t.Fatalf("list drafts = %d %#v", status, listed)
	}
	drafts := listed["drafts"].([]any)
	if len(drafts) != 1 || drafts[0].(map[string]any)["policy"].(map[string]any)["draftId"] != draftID {
		t.Fatalf("draft policy projection = %#v", listed)
	}
	status, heldDetail := do(http.MethodGet, "/webapi/v0/messages/"+draftID, nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || len(heldDetail["bcc"].([]any)) != 1 || heldDetail["bcc"].([]any)[0] != "audit@example.net" {
		t.Fatalf("held policy Draft Bcc = %d %#v", status, heldDetail)
	}

	// Only the human owner can replace and send the policy Draft. The immutable
	// message is replaced, policy metadata follows the new id, and the version
	// guards both update and final send.
	status, agentEdit := do(http.MethodPatch, "/webapi/v0/drafts/"+draftID, map[string]any{
		"draftVersion": 1, "to": []string{"recipient@example.net"},
		"bcc":     []string{"audit@example.net"},
		"subject": "Payment plan edited", "text": "Owner-reviewed payment wording.",
	}, requestAuth{bearer: agentToken})
	if status != http.StatusForbidden || agentEdit["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent policy Draft edit = %d %#v", status, agentEdit)
	}
	status, agentSend := do(http.MethodPost, "/webapi/v0/drafts/"+draftID+"/send", map[string]any{"draftVersion": 1}, requestAuth{bearer: agentToken})
	if status != http.StatusForbidden || agentSend["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent policy Draft send = %d %#v", status, agentSend)
	}
	status, agentDelete := do(http.MethodDelete, "/webapi/v0/drafts/"+draftID, nil, requestAuth{bearer: agentToken})
	if status != http.StatusForbidden || agentDelete["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent policy Draft delete = %d %#v", status, agentDelete)
	}
	status, edited := do(http.MethodPatch, "/webapi/v0/drafts/"+draftID, map[string]any{
		"draftVersion": 1, "to": []string{"recipient@example.net"},
		"bcc":     []string{"audit@example.net"},
		"subject": "Payment plan edited", "text": "Owner-reviewed payment wording.",
	}, requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusOK || edited["draftVersion"] != float64(2) || edited["id"] == draftID {
		t.Fatalf("owner policy Draft edit = %d %#v", status, edited)
	}
	editedDraftID := edited["id"].(string)
	status, staleSend := do(http.MethodPost, "/webapi/v0/drafts/"+editedDraftID+"/send", map[string]any{"draftVersion": 1}, requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusConflict || staleSend["error"].(map[string]any)["code"] != "draft_version_conflict" {
		t.Fatalf("stale policy Draft send = %d %#v", status, staleSend)
	}
	status, sentPolicyDraft := do(http.MethodPost, "/webapi/v0/drafts/"+editedDraftID+"/send", map[string]any{"draftVersion": 2}, requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusAccepted || sentPolicyDraft["messageId"] == "" {
		t.Fatalf("current policy Draft send = %d %#v", status, sentPolicyDraft)
	}
	var bccQueueRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM queue WHERE account_id=$1 AND rcpt_to='audit@example.net'`, mailAccountID).Scan(&bccQueueRows); err != nil {
		t.Fatal(err)
	}
	if bccQueueRows != 1 {
		t.Fatalf("approved policy Draft Bcc queue rows = %d, want 1", bccQueueRows)
	}
	status, sentDetail := do(http.MethodGet, "/webapi/v0/messages/"+sentPolicyDraft["messageId"].(string), nil,
		requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusOK {
		t.Fatalf("sent policy message = %d %#v", status, sentDetail)
	}
	if bcc, ok := sentDetail["bcc"]; ok && len(bcc.([]any)) > 0 {
		t.Fatalf("Sent policy message exposed Bcc: %#v", sentDetail)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_policy_drafts WHERE account_id=$1`, mailAccountID).Scan(&policyRows); err != nil {
		t.Fatal(err)
	}
	if policyRows != 0 {
		t.Fatalf("policy Draft metadata after accepted send = %d, want 0", policyRows)
	}

	// The generic Agent send path uses the same Bcc-preserving policy Draft,
	// even though its normal submission bytes keep Bcc envelope-only.
	directBody := map[string]any{
		"to": []string{"recipient@example.net"}, "bcc": []string{"hidden@example.net"},
		"subject": "Payment direct", "text": "Please review this payment directly.",
	}
	status, directReview := do(http.MethodPost, "/webapi/v0/agent-send-intents", directBody, requestAuth{
		bearer: agentToken, idempotencyKey: "direct-policy-001",
	})
	if status != http.StatusConflict || directReview["error"].(map[string]any)["code"] != "outbound_review_required" {
		t.Fatalf("direct send policy response = %d %#v", status, directReview)
	}
	directDraftID := directReview["policy"].(map[string]any)["draftId"].(string)
	status, directDetail := do(http.MethodGet, "/webapi/v0/messages/"+directDraftID, nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || len(directDetail["bcc"].([]any)) != 1 || directDetail["bcc"].([]any)[0] != "hidden@example.net" {
		t.Fatalf("direct policy Draft Bcc = %d %#v", status, directDetail)
	}

	address, _ := smtp.ParseAddress("support@example.com")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}

	// Forwarding evaluates the complete forwarded body, including the quoted
	// original message, before creating a Sent copy or queue entry. This closes
	// the alternate outbound path without changing the normal confirmation flow.
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: customer@example.net\r\nTo: support@example.com\r\nSubject: Forward source\r\nMessage-ID: <policy-forward-source@example.net>\r\n\r\nThe payment details are in the original message.\r\n")); err != nil {
		t.Fatal(err)
	}
	var forwardSourceEmailID int64
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(email_id,id) FROM messages WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, mailAccountID).Scan(&forwardSourceEmailID); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_draft`, mailAccountID).Scan(&draftMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_policy_drafts WHERE account_id=$1`, mailAccountID).Scan(&policyRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, mailAccountID).Scan(&sentMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE account_id=$1`, mailAccountID).Scan(&queueRows); err != nil {
		t.Fatal(err)
	}
	forwardDraftsBefore, forwardPolicyBefore := draftMessages, policyRows
	forwardSentBefore, forwardQueueBefore := sentMessages, queueRows
	forwardPath := "/webapi/v0/messages/E" + strconv.FormatInt(forwardSourceEmailID, 10) + "/forward"
	forwardBody := map[string]any{
		"to": []string{"recipient@example.net"}, "text": "FYI",
	}
	status, forwardDenied := do(http.MethodPost, forwardPath, forwardBody, requestAuth{
		bearer: agentToken, idempotencyKey: "forward-policy-001",
	})
	if status != http.StatusForbidden || forwardDenied["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent forward = %d %#v", status, forwardDenied)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_draft`, mailAccountID).Scan(&draftMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbound_policy_drafts WHERE account_id=$1`, mailAccountID).Scan(&policyRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, mailAccountID).Scan(&sentMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE account_id=$1`, mailAccountID).Scan(&queueRows); err != nil {
		t.Fatal(err)
	}
	if draftMessages != forwardDraftsBefore || policyRows != forwardPolicyBefore || sentMessages != forwardSentBefore || queueRows != forwardQueueBefore {
		t.Fatalf("forward side effects drafts=%d→%d policy=%d→%d sent=%d→%d queue=%d→%d",
			forwardDraftsBefore, draftMessages, forwardPolicyBefore, policyRows,
			forwardSentBefore, sentMessages, forwardQueueBefore, queueRows)
	}

	// The same evaluator applies to an owner-scoped automatic reply. It creates a
	// policy Draft and never queues the reply.
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: customer@example.net\r\nTo: support@example.com\r\nSubject: Question\r\nMessage-ID: <policy-source@example.net>\r\n\r\nCan you help?\r\n")); err != nil {
		t.Fatal(err)
	}
	var sourceEmailID int64
	if err := db.Pool.QueryRow(ctx,
		`SELECT COALESCE(email_id,id) FROM messages WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, mailAccountID).Scan(&sourceEmailID); err != nil {
		t.Fatal(err)
	}
	status, autoReview := do(http.MethodPost, "/webapi/v0/messages/E"+strconv.FormatInt(sourceEmailID, 10)+"/reply", map[string]any{
		"text": "The payment is ready for review.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-" + strconv.FormatInt(sourceEmailID, 10)})
	if status != http.StatusConflict || autoReview["policy"].(map[string]any)["source"] != outboundpolicy.SourceInboundAutoReply {
		t.Fatalf("automatic reply review = %d %#v", status, autoReview)
	}

	// A human owner write does not enter the Agent business-policy path.
	status, ownerSend := do(http.MethodPost, "/webapi/v0/messages", matchedBody, ownerAuth)
	if status != http.StatusAccepted || ownerSend["messageId"] == "" {
		t.Fatalf("owner send compatibility = %d %#v", status, ownerSend)
	}
}
