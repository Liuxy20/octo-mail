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
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreplychain"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestAgentPreparedDraftManualConfirmationFlow(t *testing.T) {
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
	scan(t, db, ctx, `INSERT INTO tenants (name) VALUES ('agent-drafts') RETURNING id`, &tenantID)
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
	chain, err := autoreplychain.New([]byte(strings.Repeat("m", 32)), 4)
	if err != nil {
		t.Fatal(err)
	}
	gatewaySecret := []byte(strings.Repeat("g", 32))
	server := &webapi.Server{
		Dir: dir, Submission: &submit.Submitter{Pool: db.Pool, Blob: bs},
		Suppressions:   &deliverability.Suppressions{Pool: db.Pool},
		AutoReplyChain: chain, GatewaySecret: gatewaySecret,
		OutboundPolicy: outboundpolicy.NewKeywordEvaluator([]string{"policy-block-phrase"}),
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	type requestAuth struct {
		basicUser, basicPassword string
		bearer, confirmation     string
		idempotencyKey           string
		automation               string
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
		if auth.idempotencyKey != "" {
			req.Header.Set("X-Octo-Idempotency-Key", auth.idempotencyKey)
		}
		if auth.automation != "" {
			req.Header.Set("X-Octo-Automation", auth.automation)
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
	if err := dir.SetPassword(ctx, "support@example.com", "support-owner-pw"); err != nil {
		t.Fatal(err)
	}

	verifier := "agent-draft-verifier-with-enough-entropy"
	verifierDigest := sha256.Sum256([]byte(verifier))
	status, device := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
		"botId": "bot-draft", "botProfile": "agent-draft", "clientName": "draft-test",
		"spaceId":       "space-a",
		"codeChallenge": base64.RawURLEncoding.EncodeToString(verifierDigest[:]),
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("create device request = %d %#v", status, device)
	}
	status, approved := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+device["userCode"].(string)+"/approve", map[string]any{
		"mailboxId": mailboxID, "outboundMode": "manual_confirmation",
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
	agentAuth := requestAuth{bearer: agentToken}
	mailboxOwnerAuth := requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"}

	status, invalidDraft := do(http.MethodPost, "/webapi/v0/agent-drafts", map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Typo", "text": "body",
		"unknownField": true,
	}, requestAuth{bearer: agentToken, idempotencyKey: "strict-agent-draft-001"})
	if status != http.StatusBadRequest || invalidDraft["error"].(map[string]any)["code"] != "invalid_body" {
		t.Fatalf("Agent Draft unknown field = %d %#v, want 400 invalid_body", status, invalidDraft)
	}

	// The Agent-specific Draft endpoint is still a producer of a sendable Draft,
	// so it must apply the same outbound policy before persisting Agent Draft
	// metadata. A blocked request creates only the owner-review policy Draft and
	// never reaches Sent or the delivery queue.
	blockedAuth := requestAuth{bearer: agentToken, idempotencyKey: "policy-agent-draft-001"}
	status, blockedDraft := do(http.MethodPost, "/webapi/v0/agent-drafts", map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Needs review", "text": "policy-block-phrase",
	}, blockedAuth)
	if status != http.StatusConflict || blockedDraft["error"].(map[string]any)["code"] != "outbound_review_required" {
		t.Fatalf("blocked Agent Draft = %d %#v", status, blockedDraft)
	}
	status, conflictingBlockedDraft := do(http.MethodPost, "/webapi/v0/agent-drafts", map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Changed review", "text": "policy-block-phrase changed",
	}, blockedAuth)
	if status != http.StatusConflict || conflictingBlockedDraft["error"].(map[string]any)["code"] != "idempotency_key_conflict" {
		t.Fatalf("conflicting policy Draft = %d %#v", status, conflictingBlockedDraft)
	}
	var blockedPolicyDrafts, blockedAgentDrafts, blockedSent, blockedQueue int
	for _, check := range []struct {
		query string
		out   *int
	}{
		{`SELECT count(*) FROM outbound_policy_drafts WHERE account_id=$1`, &blockedPolicyDrafts},
		{`SELECT count(*) FROM agent_outbound_drafts WHERE account_id=$1`, &blockedAgentDrafts},
		{`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, &blockedSent},
		{`SELECT count(*) FROM queue WHERE account_id=$1`, &blockedQueue},
	} {
		if err := db.Pool.QueryRow(ctx, check.query, mailAccountID).Scan(check.out); err != nil {
			t.Fatal(err)
		}
	}
	if blockedPolicyDrafts != 1 || blockedAgentDrafts != 0 || blockedSent != 0 || blockedQueue != 0 {
		t.Fatalf("blocked Agent Draft side effects policy=%d agent=%d sent=%d queue=%d, want 1/0/0/0",
			blockedPolicyDrafts, blockedAgentDrafts, blockedSent, blockedQueue)
	}

	// An Agent credential can inspect its mailbox, but account-management
	// mutations remain owner-only. The same endpoints keep working for the human
	// owner of the mailbox.
	status, agentAlias := do(http.MethodPost, "/webapi/v0/addresses", map[string]any{"localpart": "agent-alias"}, agentAuth)
	if status != http.StatusForbidden || agentAlias["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent alias creation = %d %#v", status, agentAlias)
	}
	status, ownerAlias := do(http.MethodPost, "/webapi/v0/addresses", map[string]any{"localpart": "owner-alias"}, mailboxOwnerAuth)
	if status != http.StatusCreated {
		t.Fatalf("owner alias creation = %d %#v", status, ownerAlias)
	}
	status, agentAliasDelete := do(http.MethodDelete, "/webapi/v0/addresses/"+ownerAlias["id"].(string), nil, agentAuth)
	if status != http.StatusForbidden || agentAliasDelete["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent alias deletion = %d %#v", status, agentAliasDelete)
	}
	status, _ = do(http.MethodDelete, "/webapi/v0/addresses/"+ownerAlias["id"].(string), nil, mailboxOwnerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("owner alias deletion = %d", status)
	}
	status, ownerSuppression := do(http.MethodPut, "/webapi/v0/suppressions/blocked@example.net", map[string]any{"reason": "owner"}, mailboxOwnerAuth)
	if status != http.StatusOK || ownerSuppression["suppressed"] != true {
		t.Fatalf("owner suppression creation = %d %#v", status, ownerSuppression)
	}
	status, agentSuppression := do(http.MethodPut, "/webapi/v0/suppressions/agent@example.net", map[string]any{"reason": "agent"}, agentAuth)
	if status != http.StatusForbidden || agentSuppression["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent suppression creation = %d %#v", status, agentSuppression)
	}
	status, agentSuppressionDelete := do(http.MethodDelete, "/webapi/v0/suppressions/blocked@example.net", nil, agentAuth)
	if status != http.StatusForbidden || agentSuppressionDelete["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent suppression deletion = %d %#v", status, agentSuppressionDelete)
	}
	status, _ = do(http.MethodDelete, "/webapi/v0/suppressions/blocked@example.net", nil, mailboxOwnerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("owner suppression deletion = %d", status)
	}

	// Generic Draft endpoints are human composition APIs. An Agent cannot use
	// them to manufacture or mutate an unmarked Draft and then replay the normal
	// operation confirmation to bypass the Agent workflow.
	plainDraftBody := map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Owner Draft", "text": "Owner-only draft.",
	}
	status, agentPlainCreate := do(http.MethodPost, "/webapi/v0/drafts", plainDraftBody, agentAuth)
	if status != http.StatusForbidden || agentPlainCreate["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent generic Draft creation = %d %#v", status, agentPlainCreate)
	}
	status, plainDraft := do(http.MethodPost, "/webapi/v0/drafts", plainDraftBody, mailboxOwnerAuth)
	if status != http.StatusCreated {
		t.Fatalf("owner generic Draft creation = %d %#v", status, plainDraft)
	}
	plainDraftID := plainDraft["id"].(string)
	status, agentPlainEdit := do(http.MethodPatch, "/webapi/v0/drafts/"+plainDraftID, map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Changed", "text": "Agent edit.",
	}, agentAuth)
	if status != http.StatusForbidden || agentPlainEdit["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent generic Draft edit = %d %#v", status, agentPlainEdit)
	}
	status, agentPlainSend := do(http.MethodPost, "/webapi/v0/drafts/"+plainDraftID+"/send", nil, agentAuth)
	if status != http.StatusForbidden || agentPlainSend["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent generic Draft send = %d %#v", status, agentPlainSend)
	}
	status, scopedPlainSend := do(http.MethodPost, "/webapi/v0/drafts/"+plainDraftID+"/send", map[string]any{"draftVersion": 1}, requestAuth{
		bearer: agentToken, automation: "owner-confirmed-draft", idempotencyKey: "owner-confirmed-plain-001",
	})
	if status != http.StatusForbidden || scopedPlainSend["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("scoped Agent generic Draft send = %d %#v", status, scopedPlainSend)
	}
	status, agentPlainDelete := do(http.MethodDelete, "/webapi/v0/drafts/"+plainDraftID, nil, agentAuth)
	if status != http.StatusForbidden || agentPlainDelete["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent generic Draft deletion = %d %#v", status, agentPlainDelete)
	}
	status, _ = do(http.MethodDelete, "/webapi/v0/drafts/"+plainDraftID, nil, mailboxOwnerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("owner generic Draft deletion = %d", status)
	}

	status, deletableAgentDraft := do(http.MethodPost, "/webapi/v0/agent-drafts", map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Discard me", "text": "Prepared by Agent.",
	}, requestAuth{bearer: agentToken, idempotencyKey: "prepare-delete-001"})
	if status != http.StatusCreated {
		t.Fatalf("prepare deletable Agent Draft = %d %#v", status, deletableAgentDraft)
	}
	deletableAgentDraftID := deletableAgentDraft["draftId"].(string)
	status, agentDraftDelete := do(http.MethodDelete, "/webapi/v0/drafts/"+deletableAgentDraftID, nil, agentAuth)
	if status != http.StatusForbidden || agentDraftDelete["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent Draft deletion = %d %#v", status, agentDraftDelete)
	}
	status, _ = do(http.MethodDelete, "/webapi/v0/drafts/"+deletableAgentDraftID, nil, mailboxOwnerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("confirmed Agent Draft deletion = %d", status)
	}

	address, _ := smtp.ParseAddress("support@example.com")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	source := &store.Message{}
	if _, err := target.Deliver(ctx, source, mem("From: customer@example.net\r\nTo: support@example.com\r\nSubject: Need help\r\nMessage-ID: <agent-draft-source@example.net>\r\n\r\nCan you help?\r\n")); err != nil {
		t.Fatal(err)
	}
	sourceID := "E" + strconv.FormatInt(source.EffectiveEmailID(), 10)

	status, automaticContext := do(http.MethodGet, "/webapi/v0/messages/"+sourceID+"/auto-reply-context", nil, agentAuth)
	if status != http.StatusOK || automaticContext["enabled"] != false {
		t.Fatalf("manual automation context = %d %#v", status, automaticContext)
	}
	status, invalidReplyDraft := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply-draft", map[string]any{
		"text": "prepared reply", "unknownField": true,
	}, requestAuth{bearer: agentToken, idempotencyKey: "strict-reply-draft-001"})
	if status != http.StatusBadRequest || invalidReplyDraft["error"].(map[string]any)["code"] != "invalid_body" {
		t.Fatalf("Agent reply Draft unknown field = %d %#v, want 400 invalid_body", status, invalidReplyDraft)
	}

	preparedBody := map[string]any{
		"to": []string{"recipient@example.net"}, "subject": "Prepared message", "text": "Owner must confirm.",
	}
	prepareAuth := requestAuth{bearer: agentToken, idempotencyKey: "prepare-send-001"}
	status, prepared := do(http.MethodPost, "/webapi/v0/agent-send-intents", preparedBody, prepareAuth)
	if status != http.StatusCreated || prepared["outcome"] != "owner_confirmation_required" || prepared["draftType"] != "agent_pending_confirmation" {
		t.Fatalf("prepare proactive Draft = %d %#v", status, prepared)
	}
	preparedID := prepared["draftId"].(string)
	status, duplicate := do(http.MethodPost, "/webapi/v0/agent-send-intents", preparedBody, prepareAuth)
	if status != http.StatusCreated || duplicate["draftId"] != preparedID {
		t.Fatalf("duplicate proactive Draft = %d %#v", status, duplicate)
	}

	status, replyDraft := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply-draft", map[string]any{
		"text": "I prepared a response.",
	}, requestAuth{bearer: agentToken, idempotencyKey: "prepare-reply-001"})
	if status != http.StatusCreated || replyDraft["draftType"] != "agent_reply_draft" || replyDraft["sourceEmailId"] != sourceID || replyDraft["threadId"] == "" {
		t.Fatalf("prepare reply Draft = %d %#v", status, replyDraft)
	}
	replyDraftID := replyDraft["draftId"].(string)
	status, replyDetail := do(http.MethodGet, "/webapi/v0/messages/"+replyDraftID, nil, agentAuth)
	if status != http.StatusOK || replyDetail["threadId"] != replyDraft["threadId"] {
		t.Fatalf("reply Draft detail = %d %#v", status, replyDetail)
	}
	if replyDetail["agentDraft"].(map[string]any)["sourceEmailId"] != sourceID {
		t.Fatalf("reply Draft projection = %#v", replyDetail)
	}

	var draftMessages, metadataRows, sentMessages, queueRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_draft`, mailAccountID).Scan(&draftMessages); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_outbound_drafts WHERE account_id=$1`, mailAccountID).Scan(&metadataRows); err != nil {
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
	if draftMessages != 3 || metadataRows != 2 || sentMessages != 0 || queueRows != 0 {
		t.Fatalf("prepared side effects drafts=%d metadata=%d sent=%d queue=%d, want 3/2/0/0", draftMessages, metadataRows, sentMessages, queueRows)
	}

	status, denied := do(http.MethodPost, "/webapi/v0/drafts/"+preparedID+"/send", map[string]any{"draftVersion": 1}, agentAuth)
	if status != http.StatusForbidden || denied["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent Draft send = %d %#v", status, denied)
	}
	status, sent := do(http.MethodPost, "/webapi/v0/drafts/"+preparedID+"/send", map[string]any{"draftVersion": 1}, requestAuth{
		bearer: agentToken, automation: "owner-confirmed-draft", idempotencyKey: "owner-confirmed-draft-001",
	})
	if status != http.StatusAccepted || sent["messageId"] == "" || sent["senderAddress"] != "support@example.com" {
		t.Fatalf("Plugin-confirmed prepared Draft = %d %#v", status, sent)
	}

	// Editing preserves the original reply thread and increments the version.
	status, edited := do(http.MethodPatch, "/webapi/v0/drafts/"+replyDraftID, map[string]any{
		"draftVersion": 1, "to": []string{"customer@example.net"},
		"subject": "Re: Need help", "text": "Owner edited this response.",
	}, requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusOK || edited["draftVersion"] != float64(2) {
		t.Fatalf("edit reply Draft = %d %#v", status, edited)
	}
	editedID := edited["id"].(string)
	status, editedDetail := do(http.MethodGet, "/webapi/v0/messages/"+editedID, nil, agentAuth)
	if status != http.StatusOK || editedDetail["threadId"] != replyDraft["threadId"] {
		t.Fatalf("edited reply Draft thread = %d %#v", status, editedDetail)
	}
	status, stale := do(http.MethodPost, "/webapi/v0/drafts/"+editedID+"/send", map[string]any{"draftVersion": 1}, requestAuth{basicUser: "support@example.com", basicPassword: "support-owner-pw"})
	if status != http.StatusConflict || stale["error"].(map[string]any)["code"] != "draft_version_conflict" {
		t.Fatalf("stale reply Draft send = %d %#v", status, stale)
	}

	// The binding is authoritative at execution time. Switching the existing
	// binding to automatic_send immediately affects the already-issued omb_
	// credential; no re-authorization or credential rotation is needed.
	status, modeUpdated := do(http.MethodPatch, "/webapi/v0/agent-mailboxes/"+mailboxID+"/automation", map[string]any{
		"outboundMode": "automatic_send",
	}, ownerAuth)
	if status != http.StatusOK || modeUpdated["outboundMode"] != "automatic_send" {
		t.Fatalf("switch outbound mode = %d %#v", status, modeUpdated)
	}
	automaticBody := map[string]any{
		"to": []string{"automatic@example.net"}, "subject": "Automatic message", "text": "Send without per-message confirmation.",
	}
	status, automaticSend := do(http.MethodPost, "/webapi/v0/agent-send-intents", automaticBody, requestAuth{bearer: agentToken, idempotencyKey: "automatic-send-001"})
	if status != http.StatusAccepted || automaticSend["outcome"] != "accepted" || automaticSend["messageId"] == "" || automaticSend["senderAddress"] != "support@example.com" {
		t.Fatalf("automatic proactive send = %d %#v", status, automaticSend)
	}
	status, repeatedAutomaticSend := do(http.MethodPost, "/webapi/v0/agent-send-intents", automaticBody, requestAuth{bearer: agentToken, idempotencyKey: "automatic-send-001"})
	if status != http.StatusAccepted || repeatedAutomaticSend["messageId"] != automaticSend["messageId"] || repeatedAutomaticSend["senderAddress"] != "support@example.com" {
		t.Fatalf("idempotent automatic proactive send = %d %#v", status, repeatedAutomaticSend)
	}
	status, conflictingAutomaticSend := do(http.MethodPost, "/webapi/v0/agent-send-intents", map[string]any{
		"to": []string{"automatic@example.net"}, "subject": "Changed", "text": "Different content.",
	}, requestAuth{bearer: agentToken, idempotencyKey: "automatic-send-001"})
	if status != http.StatusConflict || conflictingAutomaticSend["error"].(map[string]any)["code"] != "idempotency_key_conflict" {
		t.Fatalf("conflicting automatic proactive send = %d %#v", status, conflictingAutomaticSend)
	}
	var automaticQueueRows, acceptedIntentRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM queue WHERE account_id=$1 AND rcpt_to='automatic@example.net'`, mailAccountID).Scan(&automaticQueueRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM agent_send_intents WHERE account_id=$1 AND status='accepted'`, mailAccountID).Scan(&acceptedIntentRows); err != nil {
		t.Fatal(err)
	}
	if automaticQueueRows != 1 || acceptedIntentRows != 1 {
		t.Fatalf("automatic send idempotency queue=%d intents=%d, want 1/1", automaticQueueRows, acceptedIntentRows)
	}

	// An ambiguous queue COMMIT keeps both the Sent evidence and the processing
	// intent. Repeating the same key must not call submission a second time.
	var sentBeforeUnknown int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, mailAccountID).Scan(&sentBeforeUnknown); err != nil {
		t.Fatal(err)
	}
	normalSubmission := server.Submission
	unknownSubmission := &resultUnknownSubmitter{}
	server.Submission = unknownSubmission
	unknownBody := map[string]any{
		"to": []string{"unknown@example.net"}, "subject": "Unknown automatic message", "text": "Do not retry this automatically.",
	}
	status, unknownSend := do(http.MethodPost, "/webapi/v0/agent-send-intents", unknownBody, requestAuth{bearer: agentToken, idempotencyKey: "automatic-send-unknown"})
	if status != http.StatusConflict || unknownSend["error"].(map[string]any)["code"] != "send_intent_result_unknown" {
		t.Fatalf("unknown automatic send = %d %#v", status, unknownSend)
	}
	status, repeatedUnknown := do(http.MethodPost, "/webapi/v0/agent-send-intents", unknownBody, requestAuth{bearer: agentToken, idempotencyKey: "automatic-send-unknown"})
	if status != http.StatusConflict || repeatedUnknown["error"].(map[string]any)["code"] != "send_intent_result_unknown" || unknownSubmission.calls.Load() != 1 {
		t.Fatalf("repeated unknown automatic send = %d %#v calls=%d", status, repeatedUnknown, unknownSubmission.calls.Load())
	}
	server.Submission = normalSubmission
	var sentAfterUnknown, processingIntentRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`,
		mailAccountID).Scan(&sentAfterUnknown); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM agent_send_intents WHERE account_id=$1 AND idempotency_key='automatic-send-unknown' AND status='processing'`,
		mailAccountID).Scan(&processingIntentRows); err != nil {
		t.Fatal(err)
	}
	if sentAfterUnknown != sentBeforeUnknown+1 || processingIntentRows != 1 {
		t.Fatalf("unknown automatic evidence sent=%d→%d processing=%d, want +1/1", sentBeforeUnknown, sentAfterUnknown, processingIntentRows)
	}
}
