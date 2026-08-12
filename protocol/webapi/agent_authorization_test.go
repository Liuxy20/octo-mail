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
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestAgentAuthorizationBindRebindAndRevoke(t *testing.T) {
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

	var tenantID, ownerPrincipalID, ownerAccountID, unlistedPrincipalID, unlistedAccountID, otherPrincipalID, otherAccountID, domainID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('agent-auth') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@example.com') RETURNING id`, &ownerPrincipalID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'owner') RETURNING id`, &ownerAccountID, tenantID, ownerPrincipalID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'unlisted@example.com') RETURNING id`, &unlistedPrincipalID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$3,'unlisted') RETURNING id`, &unlistedAccountID, tenantID, unlistedPrincipalID, ownerPrincipalID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'other@example.com') RETURNING id`, &otherPrincipalID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'other') RETURNING id`, &otherAccountID, tenantID, otherPrincipalID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES
		 ($1,$2,$3,'owner'),($1,$2,$4,'unlisted'),($1,$2,$5,'other')`, tenantID, domainID, ownerAccountID, unlistedAccountID, otherAccountID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "owner@example.com", "owner-pw"); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, "other@example.com", "other-pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','octo-owner','space-a',$1,$2,$3),
		        ('octo-server','octo-owner','space-b',$1,$2,$3),
		        ('octo-server','octo-other','space-a',$1,$4,$5)`,
		tenantID, ownerPrincipalID, ownerAccountID, otherPrincipalID, otherAccountID); err != nil {
		t.Fatal(err)
	}

	gatewaySecret := []byte(strings.Repeat("g", 32))
	hs := httptest.NewServer((&webapi.Server{
		Dir: dir, AuthorizationURL: "https://octo.example/mail/authorize",
		GatewaySecret: gatewaySecret,
	}).Handler())
	defer hs.Close()

	type auth struct{ login, password, bearer, confirmation, gatewaySubject, spaceID string }
	do := func(method, path string, body any, a auth) (int, map[string]any) {
		var reader io.Reader
		var requestBody []byte
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			requestBody = raw
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, hs.URL+path, reader)
		if err != nil {
			t.Fatal(err)
		}
		if a.gatewaySubject != "" {
			token, err := gatewayassert.Sign(gatewaySecret, "octo-server", a.gatewaySubject, a.spaceID, method, path, requestBody, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
		} else if a.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+a.bearer)
		} else if a.login != "" {
			req.SetBasicAuth(a.login, a.password)
		}
		if a.confirmation != "" {
			req.Header.Set("X-Octo-Confirmation", a.confirmation)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var result map[string]any
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode %s %s: %v (%s)", method, path, err, raw)
			}
		}
		return resp.StatusCode, result
	}

	ownerAuth := auth{gatewaySubject: "octo-owner", spaceID: "space-a"}
	otherAuth := auth{gatewaySubject: "octo-other", spaceID: "space-a"}
	missingSpaceDigest := sha256.Sum256([]byte("missing-space-verifier"))
	status, missingSpace := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
		"botId":         "bot-missing-space",
		"codeChallenge": base64.RawURLEncoding.EncodeToString(missingSpaceDigest[:]),
	}, auth{})
	if status != http.StatusBadRequest || missingSpace["error"].(map[string]any)["code"] != "invalid_request" {
		t.Fatalf("missing Space device request = %d %#v", status, missingSpace)
	}

	status, created := do(http.MethodPost, "/webapi/v0/agent-mailboxes", map[string]any{"localpart": "support"}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create mailbox = %d %#v", status, created)
	}
	mailboxID := created["id"].(string)
	mailboxAccountID, err := strconv.ParseInt(mailboxID, 10, 64)
	if err != nil {
		t.Fatalf("mailbox id = %q", mailboxID)
	}

	start := func(botID, profile, verifier string) map[string]any {
		digest := sha256.Sum256([]byte(verifier))
		status, device := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
			"botId": botID, "botProfile": profile, "clientName": "octo-cli",
			"spaceId":       "space-a",
			"codeChallenge": base64.RawURLEncoding.EncodeToString(digest[:]),
		}, auth{})
		if status != http.StatusOK {
			t.Fatalf("start authorization = %d %#v", status, device)
		}
		verificationURL, err := url.Parse(device["verificationUriComplete"].(string))
		if err != nil || verificationURL.Query().Get("code") == "" || verificationURL.Query().Get("space_id") != "space-a" {
			t.Fatalf("verification URL = %v", device["verificationUriComplete"])
		}
		return device
	}
	startForMailbox := func(botID, profile, verifier, mailboxAddress string) map[string]any {
		digest := sha256.Sum256([]byte(verifier))
		status, device := do(http.MethodPost, "/webapi/v0/agent-auth/device", map[string]any{
			"botId": botID, "botProfile": profile, "clientName": "octo-cli",
			"spaceId":        "space-a",
			"mailboxAddress": mailboxAddress,
			"codeChallenge":  base64.RawURLEncoding.EncodeToString(digest[:]),
		}, auth{})
		if status != http.StatusOK {
			t.Fatalf("start targeted authorization = %d %#v", status, device)
		}
		verificationURL, err := url.Parse(device["verificationUriComplete"].(string))
		if err != nil || verificationURL.Query().Get("mailbox") != mailboxAddress || verificationURL.Query().Get("space_id") != "space-a" {
			t.Fatalf("targeted verification URL = %v, err=%v", device["verificationUriComplete"], err)
		}
		return device
	}

	deviceA := start("bot-a", "assistant-a", "verifier-a-with-enough-entropy")
	deviceCodeA := deviceA["deviceCode"].(string)
	userCodeA := deviceA["userCode"].(string)

	status, pending := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": deviceCodeA, "codeVerifier": "verifier-a-with-enough-entropy",
	}, auth{})
	if status != http.StatusBadRequest || pending["error"].(map[string]any)["code"] != "authorization_pending" {
		t.Fatalf("pending exchange = %d %#v", status, pending)
	}

	status, requestView := do(http.MethodGet, "/webapi/v0/agent-auth/requests/"+userCodeA, nil, ownerAuth)
	if status != http.StatusOK || requestView["request"].(map[string]any)["botId"] != "bot-a" || requestView["request"].(map[string]any)["pollIntervalSeconds"] != float64(3) {
		t.Fatalf("authorization view = %d %#v", status, requestView)
	}
	wrongSpaceAuth := auth{gatewaySubject: "octo-owner", spaceID: "space-b"}
	status, wrongSpace := do(http.MethodGet, "/webapi/v0/agent-auth/requests/"+userCodeA, nil, wrongSpaceAuth)
	if status != http.StatusForbidden || wrongSpace["error"].(map[string]any)["code"] != "authorization_space_mismatch" {
		t.Fatalf("cross-Space authorization view = %d %#v", status, wrongSpace)
	}
	status, wrongSpace = do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+userCodeA+"/approve",
		map[string]any{"mailboxId": mailboxID}, wrongSpaceAuth)
	if status != http.StatusForbidden || wrongSpace["error"].(map[string]any)["code"] != "authorization_space_mismatch" {
		t.Fatalf("cross-Space authorization approval = %d %#v", status, wrongSpace)
	}

	// Another owner cannot approve this request for the first owner's mailbox.
	status, _ = do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+userCodeA+"/approve",
		map[string]any{"mailboxId": mailboxID}, otherAuth)
	if status != http.StatusForbidden {
		t.Fatalf("cross-owner approve status = %d, want 403", status)
	}

	// Sharing an owner is not sufficient. An additional mailbox must be
	// registered in this Space or explicitly designated as its gateway default.
	unlistedDevice := start("bot-unlisted", "unlisted", "unlisted-verifier-with-enough-entropy")
	status, unlisted := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+unlistedDevice["userCode"].(string)+"/approve",
		map[string]any{"mailboxId": strconv.FormatInt(unlistedAccountID, 10)}, ownerAuth)
	if status != http.StatusForbidden || unlisted["error"].(map[string]any)["code"] != "mailbox_not_owned" {
		t.Fatalf("same-owner unlisted mailbox approval = %d %#v, want 403 mailbox_not_owned", status, unlisted)
	}

	// The active gateway default is the Space's initial Agent mailbox. It is
	// therefore selectable for Bot authorization even though it has no separate
	// agent_mailbox_registrations row.
	defaultVerifier := "default-agent-mailbox-verifier-with-enough-entropy"
	defaultDevice := start("bot-default", "default-agent", defaultVerifier)
	status, defaultApproved := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+defaultDevice["userCode"].(string)+"/approve",
		map[string]any{"mailboxId": strconv.FormatInt(ownerAccountID, 10)}, ownerAuth)
	if status != http.StatusOK || defaultApproved["approved"] != true {
		t.Fatalf("default Agent mailbox approval = %d %#v", status, defaultApproved)
	}
	status, defaultExchanged := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": defaultDevice["deviceCode"], "codeVerifier": defaultVerifier,
	}, auth{})
	if status != http.StatusOK || defaultExchanged["mailboxAddress"] != "owner@example.com" {
		t.Fatalf("default Agent mailbox exchange = %d %#v", status, defaultExchanged)
	}

	status, approved := do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+userCodeA+"/approve",
		map[string]any{"mailboxId": mailboxID, "outboundMode": "automatic_send"}, ownerAuth)
	if status != http.StatusOK || approved["approved"] != true || approved["outboundMode"] != "automatic_send" {
		t.Fatalf("approve = %d %#v", status, approved)
	}

	status, wrongVerifier := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": deviceCodeA, "codeVerifier": "wrong-verifier",
	}, auth{})
	if status != http.StatusUnauthorized || wrongVerifier["error"].(map[string]any)["code"] != "invalid_code_verifier" {
		t.Fatalf("wrong verifier = %d %#v", status, wrongVerifier)
	}

	status, exchangedA := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": deviceCodeA, "codeVerifier": "verifier-a-with-enough-entropy",
	}, auth{})
	if status != http.StatusOK || !strings.HasPrefix(exchangedA["accessToken"].(string), "omb_") || exchangedA["outboundMode"] != "automatic_send" {
		t.Fatalf("exchange A = %d %#v", status, exchangedA)
	}
	var persistedOutboundMode string
	if err := s.Pool.QueryRow(ctx,
		`SELECT outbound_mode FROM agent_bindings WHERE account_id=$1 AND status='active'`, mailboxAccountID).
		Scan(&persistedOutboundMode); err != nil || persistedOutboundMode != "automatic_send" {
		t.Fatalf("persisted outbound mode = %v, err=%v", persistedOutboundMode, err)
	}
	tokenA := exchangedA["accessToken"].(string)
	status, identity := do(http.MethodGet, "/webapi/v0/identity", nil, auth{bearer: tokenA})
	if status != http.StatusOK || identity["address"] != "support@example.com" {
		t.Fatalf("binding identity = %d %#v", status, identity)
	}

	address, err := smtp.ParseAddress("support@example.com")
	if err != nil {
		t.Fatal(err)
	}
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	source := &store.Message{}
	if _, err := target.Deliver(ctx, source, mem("From: customer@example.net\r\nTo: support@example.com\r\nSubject: Agent keyword boundary\r\nMessage-ID: <agent-keyword-boundary@example.net>\r\n\r\nBody\r\n")); err != nil {
		t.Fatal(err)
	}
	sourceID := "E" + strconv.FormatInt(source.EffectiveEmailID(), 10)
	agentAuth := auth{bearer: tokenA}
	status, allowedKeywords := do(http.MethodPatch, "/webapi/v0/messages/"+sourceID, map[string]any{
		"addKeywords": []string{`\Seen`, `\Answered`, `\Flagged`, `$Forwarded`, "agent-progress"},
	}, agentAuth)
	if status != http.StatusOK || allowedKeywords["updated"] != sourceID {
		t.Fatalf("Agent progress keyword update = %d %#v", status, allowedKeywords)
	}

	protectedKeywords := []string{`\Deleted`, `$deleted`, "DELETED", `\Draft`, `$Junk`, `$NotJunk`, `$Phishing`, `$MDNSent`}
	for _, field := range []string{"addKeywords", "removeKeywords"} {
		for _, keyword := range protectedKeywords {
			status, denied := do(http.MethodPatch, "/webapi/v0/messages/"+sourceID, map[string]any{
				field: []string{keyword},
			}, agentAuth)
			if status != http.StatusForbidden || denied["error"].(map[string]any)["code"] != "owner_required" {
				t.Fatalf("Agent %s %q = %d %#v, want owner_required", field, keyword, status, denied)
			}
		}
	}

	var seen, answered, flagged, forwarded, deleted bool
	var keywords []string
	if err := s.Pool.QueryRow(ctx,
		`SELECT f_seen,f_answered,f_flagged,f_forwarded,f_deleted,keywords
		 FROM messages WHERE account_id=$1 AND COALESCE(email_id,id)=$2`,
		mailboxAccountID, source.EffectiveEmailID()).
		Scan(&seen, &answered, &flagged, &forwarded, &deleted, &keywords); err != nil {
		t.Fatal(err)
	}
	if !seen || !answered || !flagged || !forwarded || deleted || len(keywords) != 1 || keywords[0] != "agent-progress" {
		t.Fatalf("Agent keyword state = seen:%v answered:%v flagged:%v forwarded:%v deleted:%v keywords:%v",
			seen, answered, flagged, forwarded, deleted, keywords)
	}

	status, agentRuleMutation := do(http.MethodPost, "/webapi/v0/agent-mailboxes/"+mailboxID+"/rules", map[string]any{
		"name": "agent must not configure rules", "matchSubject": "x",
		"forwardTargets": []string{"target@example.net"},
	}, auth{bearer: tokenA})
	if status != http.StatusForbidden || agentRuleMutation["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent rule mutation = %d %#v", status, agentRuleMutation)
	}

	// Agent credentials never receive a self-consumable confirmation token.
	// Manual external side effects require the separate human owner gateway.
	sendBody := map[string]any{"to": []string{"recipient@example.net"}, "subject": "Confirmation test", "text": "Original"}
	status, agentDenied := do(http.MethodPost, "/webapi/v0/messages", sendBody, auth{bearer: tokenA})
	if status != http.StatusForbidden || agentDenied["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent manual write = %d %#v", status, agentDenied)
	}
	status, selfApproved := do(http.MethodPost, "/webapi/v0/messages", sendBody, auth{bearer: tokenA, confirmation: "omc_agent_cannot_self_approve"})
	if status != http.StatusForbidden || selfApproved["error"].(map[string]any)["code"] != "owner_required" {
		t.Fatalf("Agent self approval = %d %#v", status, selfApproved)
	}
	status, directOwner := do(http.MethodPost, "/webapi/v0/messages", sendBody, ownerAuth)
	if status != http.StatusServiceUnavailable || directOwner["error"].(map[string]any)["code"] != "unavailable" {
		t.Fatalf("owner write should bypass Agent confirmation = %d %#v", status, directOwner)
	}

	status, reused := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": deviceCodeA, "codeVerifier": "verifier-a-with-enough-entropy",
	}, auth{})
	if status != http.StatusConflict || reused["error"].(map[string]any)["code"] != "authorization_used" {
		t.Fatalf("reused exchange = %d %#v", status, reused)
	}

	// Rebinding the same mailbox to Bot B invalidates Bot A atomically.
	deviceB := startForMailbox("bot-b", "assistant-b", "verifier-b-with-enough-entropy", "support@example.com")
	userCodeB := deviceB["userCode"].(string)
	status, _ = do(http.MethodPost, "/webapi/v0/agent-auth/requests/"+userCodeB+"/approve",
		map[string]any{"mailboxId": mailboxID}, ownerAuth)
	if status != http.StatusOK {
		t.Fatalf("approve B = %d", status)
	}
	status, exchangedB := do(http.MethodPost, "/webapi/v0/agent-auth/token", map[string]any{
		"deviceCode": deviceB["deviceCode"], "codeVerifier": "verifier-b-with-enough-entropy",
	}, auth{})
	if status != http.StatusOK {
		t.Fatalf("exchange B = %d %#v", status, exchangedB)
	}
	tokenB := exchangedB["accessToken"].(string)
	status, _ = do(http.MethodGet, "/webapi/v0/identity", nil, auth{bearer: tokenA})
	if status != http.StatusUnauthorized {
		t.Fatalf("old token after rebind = %d, want 401", status)
	}
	status, _ = do(http.MethodGet, "/webapi/v0/identity", nil, auth{bearer: tokenB})
	if status != http.StatusOK {
		t.Fatalf("new token after rebind = %d", status)
	}

	status, listed := do(http.MethodGet, "/webapi/v0/agent-mailboxes", nil, ownerAuth)
	if status != http.StatusOK {
		t.Fatalf("list connected mailboxes = %d %#v", status, listed)
	}
	foundConnected := false
	for _, item := range listed["mailboxes"].([]any) {
		mailbox := item.(map[string]any)
		if mailbox["id"] == mailboxID {
			foundConnected = mailbox["connectState"] == "connected" &&
				mailbox["botId"] == "bot-b" && mailbox["botProfile"] == "assistant-b" &&
				mailbox["agentName"] == "assistant-b"
		}
	}
	if !foundConnected {
		t.Fatalf("connected mailbox state missing: %#v", listed)
	}

	status, _ = do(http.MethodDelete, "/webapi/v0/agent-mailboxes/"+mailboxID+"/binding", nil, ownerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("unbind = %d", status)
	}
	status, _ = do(http.MethodGet, "/webapi/v0/identity", nil, auth{bearer: tokenB})
	if status != http.StatusUnauthorized {
		t.Fatalf("token after unbind = %d, want 401", status)
	}
}
