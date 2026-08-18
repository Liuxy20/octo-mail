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

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

func TestAgentMailboxCreationIsIndependent(t *testing.T) {
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

	var tenantID, principalID, accountID, domainID, agentDomainID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('agent-mailboxes') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id, login) VALUES ($1,'owner@example.com') RETURNING id`, &principalID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id, principal_id, owner_principal_id, name) VALUES ($1,$2,$2,'owner') RETURNING id`, &accountID, tenantID, principalID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id, domain) VALUES ($1,'mail.imocto.cn') RETURNING id`, &agentDomainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id, domain_id, account_id, localpart) VALUES ($1,$2,$3,'owner')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	// Account names are internal identifiers. An unrelated account may already
	// use the requested mailbox localpart even though the email address is free.
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO accounts (tenant_id, name) VALUES ($1,'support')`, tenantID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "owner@example.com", "pw"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','octo-owner','space-owner',$1,$2,$3)`,
		tenantID, principalID, accountID); err != nil {
		t.Fatal(err)
	}
	gatewaySecret := []byte(strings.Repeat("g", 32))
	api := &webapi.Server{
		Dir: dir, GatewaySecret: gatewaySecret, MaxAgentMailboxesPerOwnerSpace: 3,
		AgentMailboxDomain: "mail.imocto.cn",
	}
	hs := httptest.NewServer(api.Handler())
	defer hs.Close()
	do := func(method, path, body, bearer string) (int, map[string]any) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, hs.URL+path, rd)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			token, err := gatewayassert.Sign(gatewaySecret, "octo-server", "octo-owner", "space-owner", method, path, []byte(body), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
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

	status, initiallyListed := do(http.MethodGet, "/webapi/v0/agent-mailboxes", "", "")
	initialMailboxes, _ := initiallyListed["mailboxes"].([]any)
	if status != http.StatusOK || len(initialMailboxes) != 0 || initiallyListed["registeredCount"] != float64(0) {
		t.Fatalf("gateway default exposed as Agent mailbox = %d %#v", status, initiallyListed)
	}
	status, defaultAutomation := do(http.MethodPatch,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(accountID, 10)+"/automation",
		`{"outboundMode":"automatic_send"}`, "")
	if status != http.StatusForbidden || defaultAutomation["error"].(map[string]any)["code"] != "mailbox_not_owned" {
		t.Fatalf("gateway default automation = %d %#v", status, defaultAutomation)
	}

	status, created := do(http.MethodPost, "/webapi/v0/agent-mailboxes", `{"localpart":"support"}`, "")
	if status != http.StatusCreated || created["address"] != "support@mail.imocto.cn" {
		t.Fatalf("create agent mailbox = %d %#v", status, created)
	}
	createdID, err := strconv.ParseInt(created["id"].(string), 10, 64)
	if err != nil || createdID == accountID {
		t.Fatalf("created account id = %v, original = %d", created["id"], accountID)
	}
	var internalAccountName string
	if err := s.Pool.QueryRow(ctx, `SELECT name FROM accounts WHERE id=$1`, createdID).Scan(&internalAccountName); err != nil {
		t.Fatal(err)
	}
	if internalAccountName != "agent-mailbox:support@mail.imocto.cn" {
		t.Fatalf("Agent mailbox internal account name = %q", internalAccountName)
	}
	ownerScope, _, err := dir.AuthenticatePrincipal(ctx, "owner@example.com", directory.PasswordCredential("pw"))
	if err != nil {
		t.Fatal(err)
	}
	agentAccount, err := ownerScope.AccountForID(ctx, createdID)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentAccount.ReadTx(ctx, func(tx store.Tx) error {
		inbox, err := agentAccount.MailboxFind(tx, "Inbox")
		if err != nil {
			return err
		}
		if inbox == nil {
			return fmt.Errorf("new Agent mailbox has no Inbox")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	verifier := "agent-mailbox-mode-verifier-with-enough-entropy"
	digest := sha256.Sum256([]byte(verifier))
	agentDir := directory.AgentAuthorizationDirectory(dir)
	device, err := agentDir.CreateAgentAuthorization(ctx, directory.AgentAuthorizationInput{
		BotID: "support-bot", BotProfile: "support-agent", ClientName: "mode-test",
		SpaceID: "space-owner", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentDir.ApproveAgentAuthorization(ctx, principalID, "space-owner", device.UserCode, createdID, directory.AgentOutboundModeManualConfirmation); err != nil {
		t.Fatal(err)
	}
	credential, err := agentDir.ExchangeAgentAuthorization(ctx, device.DeviceCode, verifier)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, credentialID, err := agentDir.AuthenticateAgentCredential(ctx, credential.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.message.reply")
	if err != nil || allowed {
		t.Fatalf("initial auto reply allowed=%v err=%v", allowed, err)
	}
	allowed, err = agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.draft.send")
	if err != nil || !allowed {
		t.Fatalf("manual owner-confirmed Draft send allowed=%v err=%v", allowed, err)
	}

	status, updated := do(http.MethodPatch,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(createdID, 10)+"/automation",
		`{"outboundMode":"automatic_send"}`, "")
	if status != http.StatusOK || updated["outboundMode"] != "automatic_send" || updated["connectState"] != "connected" {
		t.Fatalf("enable mailbox automation = %d %#v", status, updated)
	}
	allowed, err = agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.message.reply")
	if err != nil || !allowed {
		t.Fatalf("enabled auto reply allowed=%v err=%v", allowed, err)
	}
	allowed, err = agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.message.send")
	if err != nil || !allowed {
		t.Fatalf("enabled automatic send allowed=%v err=%v", allowed, err)
	}
	allowed, err = agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.draft.send")
	if err != nil || allowed {
		t.Fatalf("automatic mode owner-confirmed Draft send allowed=%v err=%v", allowed, err)
	}
	status, listedAfterEnable := do(http.MethodGet, "/webapi/v0/agent-mailboxes", "", "")
	if status != http.StatusOK || !listedMailboxAutoReply(listedAfterEnable, created["id"].(string)) {
		t.Fatalf("mailbox automation not reflected in list = %d %#v", status, listedAfterEnable)
	}
	status, agentMutation := do(http.MethodPatch,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(createdID, 10)+"/automation",
		`{"outboundMode":"manual_confirmation"}`, credential.AccessToken)
	if status != http.StatusForbidden || agentMutation["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("Agent changed its automation mode = %d %#v", status, agentMutation)
	}
	status, unconnected := do(http.MethodPost, "/webapi/v0/agent-mailboxes", `{"localpart":"sales"}`, "")
	if status != http.StatusCreated {
		t.Fatalf("create unconnected Agent mailbox = %d %#v", status, unconnected)
	}
	unconnectedID, err := strconv.ParseInt(unconnected["id"].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	status, disconnectedMutation := do(http.MethodPatch,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(unconnectedID, 10)+"/automation",
		`{"outboundMode":"automatic_send"}`, "")
	if status != http.StatusConflict || disconnectedMutation["error"].(map[string]any)["code"] != "mailbox_not_connected" {
		t.Fatalf("unconnected mailbox automation = %d %#v", status, disconnectedMutation)
	}
	status, updated = do(http.MethodPatch,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(createdID, 10)+"/automation",
		`{"outboundMode":"manual_confirmation"}`, "")
	if status != http.StatusOK || updated["outboundMode"] != "manual_confirmation" {
		t.Fatalf("disable mailbox automation = %d %#v", status, updated)
	}
	allowed, err = agentDir.AgentAutomationAllowed(ctx, credentialID, "mail.message.reply")
	if err != nil || allowed {
		t.Fatalf("disabled auto reply allowed=%v err=%v", allowed, err)
	}
	status, listed := do(http.MethodGet, "/webapi/v0/agent-mailboxes", "", "")
	mailboxes, _ := listed["mailboxes"].([]any)
	if status != http.StatusOK || len(mailboxes) != 2 || listed["registeredCount"] != float64(2) || listed["addressDomain"] != "mail.imocto.cn" {
		t.Fatalf("list agent mailboxes = %d %#v", status, listed)
	}
	for _, item := range mailboxes {
		if item.(map[string]any)["id"] == strconv.FormatInt(accountID, 10) {
			t.Fatalf("gateway default exposed as Agent mailbox: %#v", listed)
		}
	}

	address, _ := smtp.ParseAddress("support@mail.imocto.cn")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	if target.AccountID() != createdID || target.IsAlias() {
		t.Fatalf("support target account=%d alias=%v, want account=%d alias=false", target.AccountID(), target.IsAlias(), createdID)
	}
	if _, err := target.Deliver(ctx, &store.Message{}, mem("From: client@remote.example\r\nTo: support@example.com\r\nSubject: independent\r\n\r\nhello\r\n")); err != nil {
		t.Fatal(err)
	}

	status, ownerMessages := do(http.MethodGet, "/webapi/v0/messages", "", "")
	if status != http.StatusOK || ownerMessages["total"] != float64(0) {
		t.Fatalf("owner mailbox saw support mail: %d %#v", status, ownerMessages)
	}
	supportKey, err := dir.IssueAPIKey(ctx, "support@mail.imocto.cn", "support bot")
	if err != nil {
		t.Fatal(err)
	}
	status, supportMessages := do(http.MethodGet, "/webapi/v0/messages", "", supportKey)
	if status != http.StatusOK || supportMessages["total"] != float64(1) {
		t.Fatalf("support mailbox messages = %d %#v", status, supportMessages)
	}
	status, _ = do(http.MethodDelete, "/webapi/v0/agent-mailboxes/"+strconv.FormatInt(createdID, 10), "", "")
	if status != http.StatusNoContent {
		t.Fatalf("delete connected Agent mailbox = %d", status)
	}
	if _, _, _, _, err := agentDir.AuthenticateAgentCredential(ctx, credential.AccessToken); err == nil {
		t.Fatal("deleted Agent mailbox credential still authenticates")
	}
	status, _ = do(http.MethodGet, "/webapi/v0/messages", "", supportKey)
	if status != http.StatusUnauthorized {
		t.Fatalf("deleted Agent mailbox API key status = %d, want 401", status)
	}
	if _, err := dir.ResolveInbound(ctx, address.Path()); err == nil {
		t.Fatal("deleted connected Agent mailbox still accepts inbound mail")
	}

	var principalsBefore, accountsBefore, addressesBefore, registrationsBefore int
	for _, count := range []struct {
		query string
		out   *int
	}{
		{`SELECT count(*) FROM principals`, &principalsBefore},
		{`SELECT count(*) FROM accounts`, &accountsBefore},
		{`SELECT count(*) FROM addresses`, &addressesBefore},
		{`SELECT count(*) FROM agent_mailbox_registrations`, &registrationsBefore},
	} {
		if err := s.Pool.QueryRow(ctx, count.query).Scan(count.out); err != nil {
			t.Fatal(err)
		}
	}
	api.AgentMailboxDomain = "missing.example"
	status, missingDomain := do(http.MethodPost, "/webapi/v0/agent-mailboxes", `{"localpart":"missing-domain"}`, "")
	if status != http.StatusConflict || missingDomain["error"].(map[string]any)["code"] != "agent_mailbox_domain_unavailable" {
		t.Fatalf("missing configured domain = %d %#v", status, missingDomain)
	}
	var principalsAfter, accountsAfter, addressesAfter, registrationsAfter int
	for _, count := range []struct {
		query string
		out   *int
	}{
		{`SELECT count(*) FROM principals`, &principalsAfter},
		{`SELECT count(*) FROM accounts`, &accountsAfter},
		{`SELECT count(*) FROM addresses`, &addressesAfter},
		{`SELECT count(*) FROM agent_mailbox_registrations`, &registrationsAfter},
	} {
		if err := s.Pool.QueryRow(ctx, count.query).Scan(count.out); err != nil {
			t.Fatal(err)
		}
	}
	if principalsAfter != principalsBefore || accountsAfter != accountsBefore || addressesAfter != addressesBefore || registrationsAfter != registrationsBefore {
		t.Fatalf("missing domain left partial rows: before=%d/%d/%d/%d after=%d/%d/%d/%d",
			principalsBefore, accountsBefore, addressesBefore, registrationsBefore,
			principalsAfter, accountsAfter, addressesAfter, registrationsAfter)
	}
}

func listedMailboxAutoReply(response map[string]any, mailboxID string) bool {
	mailboxes, _ := response["mailboxes"].([]any)
	for _, item := range mailboxes {
		mailbox, _ := item.(map[string]any)
		if mailbox["id"] == mailboxID {
			return mailbox["autoReplyEnabled"] == true
		}
	}
	return false
}

func TestAgentMailboxRegistrationLimitIsPerOwnerAndSpace(t *testing.T) {
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

	var tenantID, domainID int64
	scan(t, db, ctx, `INSERT INTO tenants (name) VALUES ('agent-mailbox-limit') RETURNING id`, &tenantID)
	scan(t, db, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'limit.example') RETURNING id`, &domainID, tenantID)
	type owner struct {
		principalID int64
		accountID   int64
		login       string
		subject     string
	}
	createOwner := func(subject, localpart string, spaces ...string) owner {
		out := owner{login: localpart + "@limit.example", subject: subject}
		scan(t, db, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,$2) RETURNING id`, &out.principalID, tenantID, out.login)
		scan(t, db, ctx,
			`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
			 VALUES ($1,$2,$2,$3) RETURNING id`, &out.accountID, tenantID, out.principalID, localpart)
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,$4)`,
			tenantID, domainID, out.accountID, localpart); err != nil {
			t.Fatal(err)
		}
		for _, spaceID := range spaces {
			if _, err := db.Pool.Exec(ctx,
				`INSERT INTO gateway_identities
				 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
				 VALUES ('octo-server',$1,$2,$3,$4,$5)`,
				subject, spaceID, tenantID, out.principalID, out.accountID); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	ownerA := createOwner("owner-a", "owner-a", "space-a", "space-b")
	ownerB := createOwner("owner-b", "owner-b", "space-a")
	ownerC := createOwner("owner-c", "owner-c", "space-a")
	if err := db.NewDirectory().SetPassword(ctx, ownerA.login, "pw"); err != nil {
		t.Fatal(err)
	}

	secret := []byte(strings.Repeat("l", 32))
	server := httptest.NewServer((&webapi.Server{
		Dir: db.NewDirectory(), GatewaySecret: secret,
		MaxAgentMailboxesPerOwnerSpace: 2,
	}).Handler())
	defer server.Close()
	request := func(subject, spaceID, method, path, body string) (int, map[string]any, error) {
		token, err := gatewayassert.Sign(secret, "octo-server", subject, spaceID, method, path, []byte(body), time.Now())
		if err != nil {
			return 0, nil, err
		}
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, nil, err
		}
		result := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &result); err != nil {
				return 0, nil, fmt.Errorf("decode response: %w (%s)", err, raw)
			}
		}
		return resp.StatusCode, result, nil
	}
	create := func(subject, spaceID, localpart string) (int, map[string]any) {
		status, body, err := request(subject, spaceID, http.MethodPost, "/webapi/v0/agent-mailboxes", `{"localpart":"`+localpart+`"}`)
		if err != nil {
			t.Fatal(err)
		}
		return status, body
	}
	status, defaultDelete, err := request(ownerA.subject, "space-a", http.MethodDelete,
		"/webapi/v0/agent-mailboxes/"+strconv.FormatInt(ownerA.accountID, 10), "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNotFound || defaultDelete["error"].(map[string]any)["code"] != "mailbox_not_found" {
		t.Fatalf("default mailbox delete = %d %#v", status, defaultDelete)
	}

	status, firstSpaceAMailbox := create(ownerA.subject, "space-a", "a-one")
	if status != http.StatusCreated {
		body := firstSpaceAMailbox
		t.Fatalf("create first mailbox in Space A = %d %#v", status, body)
	}
	status, secondSpaceAMailbox := create(ownerA.subject, "space-a", "a-two")
	if status != http.StatusCreated {
		t.Fatalf("create second mailbox in Space A = %d %#v", status, secondSpaceAMailbox)
	}
	status, blocked := create(ownerA.subject, "space-a", "a-three")
	if status != http.StatusConflict || blocked["error"].(map[string]any)["code"] != "agent_mailbox_limit_reached" {
		t.Fatalf("third Agent mailbox = %d %#v", status, blocked)
	}
	firstSpaceAID := firstSpaceAMailbox["id"].(string)
	status, crossSpaceDelete, err := request(ownerA.subject, "space-b", http.MethodDelete, "/webapi/v0/agent-mailboxes/"+firstSpaceAID, "")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNotFound || crossSpaceDelete["error"].(map[string]any)["code"] != "mailbox_not_found" {
		t.Fatalf("cross-Space delete = %d %#v", status, crossSpaceDelete)
	}
	status, _, err = request(ownerA.subject, "space-a", http.MethodDelete, "/webapi/v0/agent-mailboxes/"+firstSpaceAID, "")
	if err != nil || status != http.StatusNoContent {
		t.Fatalf("delete Agent mailbox = %d err=%v", status, err)
	}
	deletedAddress, _ := smtp.ParseAddress("a-one@limit.example")
	if _, err := db.NewDirectory().ResolveInbound(ctx, deletedAddress.Path()); err == nil {
		t.Fatal("deleted Agent mailbox still accepted inbound mail")
	}
	if status, body := create(ownerA.subject, "space-a", "a-replacement"); status != http.StatusCreated {
		t.Fatalf("released Space slot was not reusable = %d %#v", status, body)
	}
	if status, body := create(ownerA.subject, "space-b", "a-b-one"); status != http.StatusCreated {
		t.Fatalf("create first mailbox in Space B = %d %#v", status, body)
	}
	if status, body := create(ownerA.subject, "space-b", "a-b-two"); status != http.StatusCreated {
		t.Fatalf("create second mailbox in Space B = %d %#v", status, body)
	}
	if status, body := create(ownerA.subject, "space-b", "a-b-three"); status != http.StatusConflict || body["error"].(map[string]any)["code"] != "agent_mailbox_limit_reached" {
		t.Fatalf("third mailbox in Space B = %d %#v", status, body)
	}
	if status, body := create(ownerB.subject, "space-a", "b-one"); status != http.StatusCreated {
		t.Fatalf("create first mailbox for owner B = %d %#v", status, body)
	}
	if status, body := create(ownerB.subject, "space-a", "b-two"); status != http.StatusCreated {
		t.Fatalf("create second mailbox for owner B = %d %#v", status, body)
	}
	if status, body := create(ownerB.subject, "space-a", "b-three"); status != http.StatusConflict || body["error"].(map[string]any)["code"] != "agent_mailbox_limit_reached" {
		t.Fatalf("third mailbox for owner B = %d %#v", status, body)
	}

	for _, test := range []struct {
		subject, spaceID string
		want             int
	}{{ownerA.subject, "space-a", 2}, {ownerA.subject, "space-b", 2}, {ownerB.subject, "space-a", 2}} {
		status, body, err := request(test.subject, test.spaceID, http.MethodGet, "/webapi/v0/agent-mailboxes", "")
		if err != nil {
			t.Fatal(err)
		}
		mailboxes, _ := body["mailboxes"].([]any)
		if status != http.StatusOK || len(mailboxes) != test.want || body["maxMailboxes"] != float64(2) || body["registeredCount"] != float64(test.want) || body["addressDomain"] != "limit.example" {
			t.Fatalf("list %s/%s = %d %#v", test.subject, test.spaceID, status, body)
		}
	}

	// The principal row lock makes the count-and-create section safe across
	// concurrent requests and server instances sharing PostgreSQL.
	statuses := make(chan int, 8)
	for i := 0; i < cap(statuses); i++ {
		go func(i int) {
			status, _, err := request(ownerC.subject, "space-a", http.MethodPost, "/webapi/v0/agent-mailboxes", fmt.Sprintf(`{"localpart":"c-%d"}`, i))
			if err != nil {
				statuses <- 0
				return
			}
			statuses <- status
		}(i)
	}
	created := 0
	for i := 0; i < cap(statuses); i++ {
		switch status := <-statuses; status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
		default:
			t.Fatalf("concurrent create status = %d", status)
		}
	}
	if created != 2 {
		t.Fatalf("concurrent creates succeeded = %d, want 2", created)
	}

	// Direct human credentials have no verified OCTO Space and cannot bypass
	// the per-Space limit by calling octo-mail directly.
	req, err := http.NewRequest(http.MethodPost, server.URL+"/webapi/v0/agent-mailboxes", strings.NewReader(`{"localpart":"bypass"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(ownerA.login, "pw")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var missingSpace map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&missingSpace); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden || missingSpace["error"].(map[string]any)["code"] != "space_required" {
		t.Fatalf("missing Space create = %d %#v", resp.StatusCode, missingSpace)
	}
}
