package webapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreplychain"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestAgentAutomaticReplyChainStopsBeforeSideEffects(t *testing.T) {
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
	scan(t, db, ctx, `INSERT INTO tenants (name) VALUES ('auto-reply-chain') RETURNING id`, &tenantID)
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
	chain, err := autoreplychain.New([]byte(strings.Repeat("k", 32)), 4)
	if err != nil {
		t.Fatal(err)
	}
	ruleAuthenticator, err := rulemetadata.New([]byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	gatewaySecret := []byte(strings.Repeat("g", 32))
	server := &webapi.Server{
		Dir: dir, Submission: &submit.Submitter{Pool: db.Pool, Blob: bs},
		AutoReplyChain: chain, RuleMetadata: ruleAuthenticator,
		GatewaySecret: gatewaySecret, MaxAgentMailboxesPerOwnerSpace: 3,
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	type requestAuth struct {
		basicUser, basicPassword string
		bearer                   string
		confirmation             string
		automation               bool
		idempotencyKey           string
		gatewaySubject, spaceID  string
		gatewayMailbox           string
	}
	do := func(method, path string, body any, auth requestAuth) (int, map[string]any, []byte) {
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
			token, err := gatewayassert.SignForMailbox(gatewaySecret, "octo-server", auth.gatewaySubject, auth.spaceID, auth.gatewayMailbox, method, path, requestBody, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			if auth.gatewayMailbox != "" {
				req.Header.Set("X-Octo-Mailbox-ID", auth.gatewayMailbox)
			}
		} else if auth.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+auth.bearer)
		} else if auth.basicUser != "" {
			req.SetBasicAuth(auth.basicUser, auth.basicPassword)
		}
		if auth.automation {
			req.Header.Set("X-Octo-Automation", "auto-reply")
		}
		if auth.confirmation != "" {
			req.Header.Set("X-Octo-Confirmation", auth.confirmation)
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
		if strings.Contains(response.Header.Get("Content-Type"), "application/json") && len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode %s %s: %v (%s)", method, path, err, raw)
			}
		}
		return response.StatusCode, result, raw
	}

	ownerAuth := requestAuth{gatewaySubject: "octo-owner", spaceID: "space-a"}
	status, mailbox, _ := do(http.MethodPost, "/webapi/v0/agent-mailboxes", map[string]any{"localpart": "support"}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create Agent mailbox = %d %#v", status, mailbox)
	}
	mailboxID := mailbox["id"].(string)
	mailAccountID, err := strconv.ParseInt(mailboxID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	verifier := "auto-reply-chain-verifier-with-enough-entropy"
	verifierDigest := sha256.Sum256([]byte(verifier))
	status, device, _ := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
		"botId": "bot-chain", "botProfile": "agent-chain", "clientName": "chain-test",
		"spaceId":       "space-a",
		"codeChallenge": base64.RawURLEncoding.EncodeToString(verifierDigest[:]),
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("create device request = %d %#v", status, device)
	}
	status, approved, _ := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+device["userCode"].(string)+"/approve", map[string]any{
		"mailboxId": mailboxID, "outboundMode": "automatic_send",
	}, ownerAuth)
	if status != http.StatusOK || approved["approved"] != true {
		t.Fatalf("approve device = %d %#v", status, approved)
	}
	status, exchanged, _ := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": device["deviceCode"], "codeVerifier": verifier,
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("exchange device = %d %#v", status, exchanged)
	}
	agentToken := exchanged["accessToken"].(string)

	address, _ := smtp.ParseAddress("support@example.com")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	sourceRaw := signedAutomaticReplySource(t, chain, 3)
	source := &store.Message{}
	_, err = target.Deliver(ctx, source, mem(string(sourceRaw)))
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "E" + strconv.FormatInt(source.EffectiveEmailID(), 10)

	// A credential bound to another Agent mailbox in the same tenant cannot use
	// the context endpoint to inspect this mailbox's message.
	status, otherMailbox, _ := do(http.MethodPost, "/webapi/v0/agent-mailboxes", map[string]any{"localpart": "sales"}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create other Agent mailbox = %d %#v", status, otherMailbox)
	}
	status, otherDevice, _ := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
		"botId": "bot-chain-other", "botProfile": "agent-chain-other", "clientName": "chain-other-test",
		"spaceId":       "space-a",
		"codeChallenge": base64.RawURLEncoding.EncodeToString(verifierDigest[:]),
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("create other device request = %d %#v", status, otherDevice)
	}
	status, otherApproved, _ := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+otherDevice["userCode"].(string)+"/approve", map[string]any{
		"mailboxId": otherMailbox["id"], "outboundMode": "automatic_send",
	}, ownerAuth)
	if status != http.StatusOK || otherApproved["approved"] != true {
		t.Fatalf("approve other device = %d %#v", status, otherApproved)
	}
	status, otherExchanged, _ := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": otherDevice["deviceCode"], "codeVerifier": verifier,
	}, requestAuth{})
	if status != http.StatusOK {
		t.Fatalf("exchange other device = %d %#v", status, otherExchanged)
	}
	status, otherContext, _ := do(http.MethodGet, "/webapi/v0/messages/"+sourceID+"/auto-reply-context", nil, requestAuth{bearer: otherExchanged["accessToken"].(string)})
	if status != http.StatusNotFound {
		t.Fatalf("cross-mailbox context = %d %#v", status, otherContext)
	}

	status, contextResult, _ := do(http.MethodGet, "/webapi/v0/messages/"+sourceID+"/auto-reply-context", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || contextResult["autoReplyCount"] != float64(3) || contextResult["nextReplyIsFinal"] != true || contextResult["limitReached"] != false {
		t.Fatalf("count-three context = %d %#v", status, contextResult)
	}

	// A human-owner reply is a manual write and must not inherit or advance the
	// automatic-reply chain even when its source carries valid chain metadata.
	manualBody := map[string]any{"text": "This is an explicitly confirmed manual reply."}
	status, agentManualDenied, _ := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply", manualBody, requestAuth{bearer: agentToken})
	if status != http.StatusForbidden || agentManualDenied["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent manual reply = %d %#v", status, agentManualDenied)
	}
	status, manualAccepted, _ := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply", manualBody, requestAuth{
		gatewaySubject: "octo-owner", spaceID: "space-a", gatewayMailbox: mailboxID,
	})
	if status != http.StatusAccepted {
		t.Fatalf("confirmed manual reply = %d %#v", status, manualAccepted)
	}
	status, _, manualRaw := do(http.MethodGet, "/webapi/v0/messages/"+manualAccepted["messageId"].(string)+"/raw", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK {
		t.Fatalf("read manual sent raw = %d", status)
	}
	if manualContext := chain.Verify(manualRaw, "support@example.com", time.Now()); manualContext.Verification != autoreplychain.VerificationMissing {
		t.Fatalf("manual reply unexpectedly joined automatic chain: %#v", manualContext)
	}

	status, accepted, _ := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply", map[string]any{
		"text": "这里是最终结论。",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-final"})
	if status != http.StatusAccepted {
		t.Fatalf("final automatic reply = %d %#v", status, accepted)
	}
	sentID := accepted["messageId"].(string)
	// Idempotency is based on the caller's exact request. Changing the server's
	// final-reply threshold must not make an accepted retry conflict merely
	// because the server would now append different generated text.
	reconfiguredChain, err := autoreplychain.New([]byte(strings.Repeat("k", 32)), 5)
	if err != nil {
		t.Fatal(err)
	}
	server.AutoReplyChain = reconfiguredChain
	status, repeated, _ := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply", map[string]any{
		"text": "这里是最终结论。",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-final"})
	if status != http.StatusAccepted || repeated["messageId"] != sentID {
		t.Fatalf("repeated automatic reply = %d %#v, want existing %s", status, repeated, sentID)
	}
	server.AutoReplyChain = chain
	status, conflicting, _ := do(http.MethodPost, "/webapi/v0/messages/"+sourceID+"/reply", map[string]any{
		"text": "不同的回复内容。",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-final"})
	if status != http.StatusConflict || conflicting["error"].(map[string]any)["code"] != "idempotency_key_conflict" {
		t.Fatalf("conflicting automatic reply = %d %#v", status, conflicting)
	}
	var acceptedAutoReplies, acceptedAutoReplyQueueRows int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM agent_send_intents WHERE account_id=$1 AND idempotency_key='auto-reply-final' AND status='accepted'`,
		mailAccountID).Scan(&acceptedAutoReplies); err != nil {
		t.Fatal(err)
	}
	if acceptedAutoReplies != 1 {
		t.Fatalf("accepted automatic reply intents = %d, want 1", acceptedAutoReplies)
	}
	sentNumericID, _ := strconv.ParseInt(strings.TrimPrefix(sentID, "E"), 10, 64)
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM queue WHERE account_id=$1 AND message_id=$2`,
		mailAccountID, sentNumericID).Scan(&acceptedAutoReplyQueueRows); err != nil {
		t.Fatal(err)
	}
	if acceptedAutoReplyQueueRows != 1 {
		t.Fatalf("automatic reply queue rows = %d, want 1", acceptedAutoReplyQueueRows)
	}
	status, _, sentRaw := do(http.MethodGet, "/webapi/v0/messages/"+sentID+"/raw", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK {
		t.Fatalf("read final sent raw = %d", status)
	}
	verified := chain.Verify(sentRaw, "bot-a@example.net", time.Now())
	if verified.Verification != autoreplychain.VerificationValid || verified.Count != 4 {
		t.Fatalf("final sent metadata = %#v", verified)
	}
	if !bytes.Contains(sentRaw, []byte(autoreplychain.FinalNotice)) || !bytes.Contains(sentRaw, []byte("Auto-Submitted: auto-replied")) {
		t.Fatalf("final sent message missing closing notice or Auto-Submitted: %.500q", sentRaw)
	}

	limitSource := &store.Message{}
	_, err = target.Deliver(ctx, limitSource, mem(string(sentRaw)))
	if err != nil {
		t.Fatal(err)
	}
	limitSourceID := "E" + strconv.FormatInt(limitSource.EffectiveEmailID(), 10)
	status, limitContext, _ := do(http.MethodGet, "/webapi/v0/messages/"+limitSourceID+"/auto-reply-context", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || limitContext["autoReplyCount"] != float64(4) || limitContext["limitReached"] != true {
		t.Fatalf("limit context = %d %#v", status, limitContext)
	}

	var sentBefore, queueBefore, draftsBefore int
	counts := func(sent, queue, drafts *int) {
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent`, mailAccountID).Scan(sent); err != nil {
			t.Fatal(err)
		}
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE account_id=$1`, mailAccountID).Scan(queue); err != nil {
			t.Fatal(err)
		}
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_draft`, mailAccountID).Scan(drafts); err != nil {
			t.Fatal(err)
		}
	}
	counts(&sentBefore, &queueBefore, &draftsBefore)
	status, blocked, _ := do(http.MethodPost, "/webapi/v0/messages/"+limitSourceID+"/reply", map[string]any{
		"text": "This must not be sent.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-blocked"})
	if status != http.StatusConflict || blocked["error"].(map[string]any)["code"] != "auto_reply_limit_reached" {
		t.Fatalf("blocked automatic reply = %d %#v", status, blocked)
	}
	var sentAfter, queueAfter, draftsAfter int
	counts(&sentAfter, &queueAfter, &draftsAfter)
	if sentAfter != sentBefore || queueAfter != queueBefore || draftsAfter != draftsBefore {
		t.Fatalf("limit created side effects sent %d→%d queue %d→%d drafts %d→%d", sentBefore, sentAfter, queueBefore, queueAfter, draftsBefore, draftsAfter)
	}

	externalAutomatedRaw := []byte("From: vacation@example.net\r\nTo: support@example.com\r\nSubject: away\r\n" +
		"Message-ID: <vacation@example.net>\r\nAuto-Submitted: auto-replied\r\n\r\nI am away.\r\n")
	externalAutomated := &store.Message{}
	if _, err := target.Deliver(ctx, externalAutomated, mem(string(externalAutomatedRaw))); err != nil {
		t.Fatal(err)
	}
	externalAutomatedID := "E" + strconv.FormatInt(externalAutomated.EffectiveEmailID(), 10)
	status, externalContext, _ := do(http.MethodGet, "/webapi/v0/messages/"+externalAutomatedID+"/auto-reply-context", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || externalContext["autoReplyCount"] != float64(4) || externalContext["limitReached"] != true {
		t.Fatalf("external automated context = %d %#v", status, externalContext)
	}
	counts(&sentBefore, &queueBefore, &draftsBefore)
	status, externalBlocked, _ := do(http.MethodPost, "/webapi/v0/messages/"+externalAutomatedID+"/reply", map[string]any{
		"text": "This must not restart the chain.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "external-auto-reply-blocked"})
	if status != http.StatusConflict || externalBlocked["error"].(map[string]any)["code"] != "auto_reply_limit_reached" {
		t.Fatalf("external automatic reply = %d %#v", status, externalBlocked)
	}
	counts(&sentAfter, &queueAfter, &draftsAfter)
	if sentAfter != sentBefore || queueAfter != queueBefore || draftsAfter != draftsBefore {
		t.Fatalf("external auto-reply created side effects sent %d→%d queue %d→%d drafts %d→%d", sentBefore, sentAfter, queueBefore, queueAfter, draftsBefore, draftsAfter)
	}

	trustedForwardRaw := signedRuleForwardSource(t, ruleAuthenticator, "support@example.com")
	trustedForward := &store.Message{}
	if _, err := target.Deliver(ctx, trustedForward, mem(string(trustedForwardRaw))); err != nil {
		t.Fatal(err)
	}
	trustedForwardID := "E" + strconv.FormatInt(trustedForward.EffectiveEmailID(), 10)
	status, trustedContext, _ := do(http.MethodGet, "/webapi/v0/messages/"+trustedForwardID+"/auto-reply-context", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || trustedContext["autoReplyCount"] != float64(0) || trustedContext["limitReached"] != false || trustedContext["enabled"] != true {
		t.Fatalf("trusted forward context = %d %#v", status, trustedContext)
	}
	status, trustedReply, _ := do(http.MethodPost, "/webapi/v0/messages/"+trustedForwardID+"/reply", map[string]any{
		"text": "Reply to the direct forwarding mailbox.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "trusted-forward-reply"})
	if status != http.StatusAccepted {
		t.Fatalf("trusted forward automatic reply = %d %#v", status, trustedReply)
	}
	status, _, trustedReplyRaw := do(http.MethodGet, "/webapi/v0/messages/"+trustedReply["messageId"].(string)+"/raw", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK {
		t.Fatalf("read trusted forward reply = %d", status)
	}
	trustedReplyContext := chain.Verify(trustedReplyRaw, "upstream@example.net", time.Now())
	if trustedReplyContext.Verification != autoreplychain.VerificationValid || trustedReplyContext.Count != 1 {
		t.Fatalf("trusted forward reply metadata = %#v", trustedReplyContext)
	}

	// SMTP may deliver the same signed forwarding message more than once, each
	// time under a different local Email id. Its signed Message-ID, rather than
	// the local id or caller-supplied retry key, is the automatic-reply identity.
	trustedReplay := &store.Message{}
	if _, err := target.Deliver(ctx, trustedReplay, mem(string(trustedForwardRaw))); err != nil {
		t.Fatal(err)
	}
	trustedReplayID := "E" + strconv.FormatInt(trustedReplay.EffectiveEmailID(), 10)
	counts(&sentBefore, &queueBefore, &draftsBefore)
	status, repeatedTrustedReply, _ := do(http.MethodPost, "/webapi/v0/messages/"+trustedReplayID+"/reply", map[string]any{
		"text": "Reply to the direct forwarding mailbox.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "different-caller-retry-key"})
	if status != http.StatusAccepted || repeatedTrustedReply["messageId"] != trustedReply["messageId"] {
		t.Fatalf("replayed trusted forward reply = %d %#v, want existing %#v", status, repeatedTrustedReply, trustedReply)
	}
	counts(&sentAfter, &queueAfter, &draftsAfter)
	if sentAfter != sentBefore || queueAfter != queueBefore || draftsAfter != draftsBefore {
		t.Fatalf("trusted replay created side effects sent %d→%d queue %d→%d drafts %d→%d", sentBefore, sentAfter, queueBefore, queueAfter, draftsBefore, draftsAfter)
	}
	status, trustedConflict, _ := do(http.MethodPost, "/webapi/v0/messages/"+trustedReplayID+"/reply", map[string]any{
		"text": "A different automatic reply must not be sent twice.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "another-caller-retry-key"})
	if status != http.StatusConflict || trustedConflict["error"].(map[string]any)["code"] != "idempotency_key_conflict" {
		t.Fatalf("conflicting trusted replay = %d %#v", status, trustedConflict)
	}

	// Human-owner replies are not part of automatic-reply deduplication.
	status, manualTrustedReply, _ := do(http.MethodPost, "/webapi/v0/messages/"+trustedReplayID+"/reply", map[string]any{
		"text": "A manually confirmed reply remains allowed.",
	}, requestAuth{gatewaySubject: "octo-owner", spaceID: "space-a", gatewayMailbox: mailboxID})
	if status != http.StatusAccepted {
		t.Fatalf("manual trusted replay reply = %d %#v", status, manualTrustedReply)
	}

	// Identical visible content with a newly signed Message-ID is a new message
	// and may independently trigger an automatic reply.
	secondTrustedRaw := signedRuleForwardSourceWithMessageID(t, ruleAuthenticator, "support@example.com", "<trusted-forward-2@example.net>")
	secondTrusted := &store.Message{}
	if _, err := target.Deliver(ctx, secondTrusted, mem(string(secondTrustedRaw))); err != nil {
		t.Fatal(err)
	}
	secondTrustedID := "E" + strconv.FormatInt(secondTrusted.EffectiveEmailID(), 10)
	status, secondTrustedReply, _ := do(http.MethodPost, "/webapi/v0/messages/"+secondTrustedID+"/reply", map[string]any{
		"text": "Reply to the direct forwarding mailbox.",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "second-trusted-message"})
	if status != http.StatusAccepted || secondTrustedReply["messageId"] == trustedReply["messageId"] {
		t.Fatalf("new trusted Message-ID reply = %d %#v", status, secondTrustedReply)
	}

	forgedRaw := []byte("From: attacker@example.net\r\nTo: support@example.com\r\nSubject: forged\r\nMessage-ID: <forged@example.net>\r\n" +
		autoreplychain.HeaderTraceID + ": attacker\r\n" + autoreplychain.HeaderCount + ": 4\r\n" +
		autoreplychain.HeaderSignature + ": v1.invalid\r\n\r\nhello\r\n")
	forged := &store.Message{}
	_, err = target.Deliver(ctx, forged, mem(string(forgedRaw)))
	if err != nil {
		t.Fatal(err)
	}
	forgedID := "E" + strconv.FormatInt(forged.EffectiveEmailID(), 10)
	status, forgedContext, _ := do(http.MethodGet, "/webapi/v0/messages/"+forgedID+"/auto-reply-context", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK || forgedContext["autoReplyCount"] != float64(0) || forgedContext["limitReached"] != false {
		t.Fatalf("forged context = %d %#v", status, forgedContext)
	}

	// A zero configured maximum leaves AutoReplyChain nil. That disables only
	// OCTO's counter; RFC 3834 still requires the outgoing automatic reply to be
	// labelled so a remote vacation responder does not treat it as human mail.
	server.AutoReplyChain = nil
	unlimitedSource := &store.Message{}
	if _, err := target.Deliver(ctx, unlimitedSource, mem("From: sender@example.net\r\nTo: support@example.com\r\nSubject: unlimited\r\nMessage-ID: <unlimited@example.net>\r\n\r\nhello\r\n")); err != nil {
		t.Fatal(err)
	}
	unlimitedSourceID := "E" + strconv.FormatInt(unlimitedSource.EffectiveEmailID(), 10)
	status, unlimitedAccepted, _ := do(http.MethodPost, "/webapi/v0/messages/"+unlimitedSourceID+"/reply", map[string]any{
		"text": "automatic reply without a local count limit",
	}, requestAuth{bearer: agentToken, automation: true, idempotencyKey: "auto-reply-unlimited"})
	if status != http.StatusAccepted {
		t.Fatalf("unlimited automatic reply = %d %#v", status, unlimitedAccepted)
	}
	status, _, unlimitedRaw := do(http.MethodGet, "/webapi/v0/messages/"+unlimitedAccepted["messageId"].(string)+"/raw", nil, requestAuth{bearer: agentToken})
	if status != http.StatusOK {
		t.Fatalf("read unlimited sent raw = %d", status)
	}
	if !bytes.Contains(unlimitedRaw, []byte("Auto-Submitted: auto-replied")) {
		t.Fatalf("unlimited automatic reply missing Auto-Submitted: %.500q", unlimitedRaw)
	}
	if bytes.Contains(unlimitedRaw, []byte(autoreplychain.HeaderTraceID+":")) {
		t.Fatalf("unlimited automatic reply unexpectedly carried count-chain metadata: %.500q", unlimitedRaw)
	}
}

func signedRuleForwardSource(t *testing.T, authenticator *rulemetadata.Authenticator, recipient string) []byte {
	return signedRuleForwardSourceWithMessageID(t, authenticator, recipient, "<trusted-forward@example.net>")
}

func signedRuleForwardSourceWithMessageID(t *testing.T, authenticator *rulemetadata.Authenticator, recipient, messageID string) []byte {
	t.Helper()
	metadata := rulemetadata.Metadata{
		OriginalFrom: "customer@example.net", SentBy: "upstream@example.net",
		RuleID: 77, Hop: 1, RuleTrace: []int64{77},
		MessageID: messageID, Recipients: []string{recipient},
		ExpiresAt: rulemetadata.Expiry(time.Now()),
	}
	trace, err := rulemetadata.FormatRuleTrace(metadata.RuleTrace)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := rulemetadata.CanonicalRecipients(metadata.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: upstream@example.net\r\nTo: " + recipient + "\r\nSubject: forwarded\r\n" +
		"Message-ID: " + metadata.MessageID + "\r\nAuto-Submitted: auto-generated\r\n" +
		rulemetadata.HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
		rulemetadata.HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
		rulemetadata.HeaderRuleID + ": 77\r\n" + rulemetadata.HeaderRuleHop + ": 1\r\n" +
		rulemetadata.HeaderRuleTrace + ": " + trace + "\r\n" +
		rulemetadata.HeaderRecipients + ": " + recipients + "\r\n" +
		rulemetadata.HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n\r\nforwarded body\r\n")
	signature, err := authenticator.Sign(metadata, raw)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.Replace(string(raw), "\r\n\r\n", "\r\n"+rulemetadata.HeaderSignature+": "+signature+"\r\n\r\n", 1))
}

func signedAutomaticReplySource(t *testing.T, chain *autoreplychain.Chain, count int) []byte {
	t.Helper()
	raw := []byte("From: bot-a@example.net\r\nTo: support@example.com\r\nSubject: chain\r\nMessage-ID: <initial@example.net>\r\n\r\nstart\r\n")
	for i := 1; i <= count; i++ {
		messageID := fmt.Sprintf("<chain-%d@example.net>", i)
		metadata, _, err := chain.Next(raw, messageID, "support@example.com", "support@example.com", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var headers strings.Builder
		headers.WriteString("From: bot-a@example.net\r\nTo: support@example.com\r\nSubject: chain\r\nMessage-ID: " + messageID + "\r\n")
		for name, value := range autoreplychain.Headers(metadata) {
			headers.WriteString(name + ": " + value + "\r\n")
		}
		headers.WriteString("\r\nreply\r\n")
		raw = []byte(headers.String())
	}
	return raw
}
