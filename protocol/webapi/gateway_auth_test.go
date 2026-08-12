package webapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

func TestGatewayIdentityIsExactToUserSpaceAndOwnedAccount(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer store.Close()
	if _, err := store.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	var tenantID, domainID int64
	scan(t, store, ctx, `INSERT INTO tenants (name) VALUES ('gateway-test') RETURNING id`, &tenantID)
	scan(t, store, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'demo.octo.test') RETURNING id`, &domainID, tenantID)
	type owner struct {
		principalID int64
		accountID   int64
		login       string
	}
	createOwner := func(localpart string) owner {
		var out owner
		out.login = localpart + "@demo.octo.test"
		scan(t, store, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,$2) RETURNING id`, &out.principalID, tenantID, out.login)
		scan(t, store, ctx,
			`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
			 VALUES ($1,$2,$2,$3) RETURNING id`, &out.accountID, tenantID, out.principalID, localpart)
		if _, err := store.Pool.Exec(ctx,
			`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,$4)`,
			tenantID, domainID, out.accountID, localpart); err != nil {
			t.Fatal(err)
		}
		return out
	}
	ownerA := createOwner("user-a")
	ownerB := createOwner("user-b")
	var agentPrincipalID, agentAccountID int64
	scan(t, store, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent-a@demo.octo.test') RETURNING id`, &agentPrincipalID, tenantID)
	scan(t, store, ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$3,'agent-a') RETURNING id`, &agentAccountID, tenantID, agentPrincipalID, ownerA.principalID)
	if _, err := store.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'agent-a')`,
		tenantID, domainID, agentAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx,
		`INSERT INTO agent_mailbox_registrations (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,'space-a')`, tenantID, agentAccountID, ownerA.principalID); err != nil {
		t.Fatal(err)
	}
	for subject, owner := range map[string]owner{"octo-user-a": ownerA, "octo-user-b": ownerB} {
		if _, err := store.Pool.Exec(ctx,
			`INSERT INTO gateway_identities
			 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
			 VALUES ('octo-server',$1,'space-a',$2,$3,$4)`,
			subject, tenantID, owner.principalID, owner.accountID); err != nil {
			t.Fatal(err)
		}
	}

	secret := []byte(strings.Repeat("g", 32))
	httpServer := httptest.NewServer((&webapi.Server{
		Dir: store.NewDirectory(), GatewaySecret: secret,
		Submission: &submit.Submitter{Pool: store.Pool, Blob: bs},
	}).Handler())
	defer httpServer.Close()
	request := func(subject, spaceID, path, selectedAccount string) (int, map[string]any) {
		token, err := gatewayassert.SignForMailbox(secret, "octo-server", subject, spaceID, selectedAccount, http.MethodGet, path, nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodGet, httpServer.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if selectedAccount != "" {
			req.Header.Set("X-Octo-Mailbox-ID", selectedAccount)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var result map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}

	status, identity := request("octo-user-a", "space-a", "/webapi/v0/identity", "")
	if status != http.StatusOK || identity["address"] != ownerA.login {
		t.Fatalf("user A identity = %d %#v", status, identity)
	}
	status, identity = request("octo-user-b", "space-a", "/webapi/v0/identity", "")
	if status != http.StatusOK || identity["address"] != ownerB.login {
		t.Fatalf("user B identity = %d %#v", status, identity)
	}
	status, identity = request("octo-user-a", "space-a", "/webapi/v0/identity", strconv.FormatInt(agentAccountID, 10))
	if status != http.StatusOK || identity["address"] != "agent-a@demo.octo.test" {
		t.Fatalf("selected Agent mailbox identity = %d %#v", status, identity)
	}

	replayPath := "/webapi/v0/identity"
	replayToken, err := gatewayassert.Sign(secret, "octo-server", "octo-user-a", "space-a", http.MethodGet, replayPath, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	callWithToken := func(token, mailbox string) int {
		req, reqErr := http.NewRequest(http.MethodGet, httpServer.URL+replayPath, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if mailbox != "" {
			req.Header.Set("X-Octo-Mailbox-ID", mailbox)
		}
		resp, callErr := http.DefaultClient.Do(req)
		if callErr != nil {
			t.Fatal(callErr)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if got := callWithToken(replayToken, ""); got != http.StatusOK {
		t.Fatalf("first gateway assertion use = %d", got)
	}
	if got := callWithToken(replayToken, ""); got != http.StatusUnauthorized {
		t.Fatalf("replayed gateway assertion = %d, want 401", got)
	}

	mailboxToken, err := gatewayassert.SignForMailbox(secret, "octo-server", "octo-user-a", "space-a", strconv.FormatInt(agentAccountID, 10), http.MethodGet, replayPath, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := callWithToken(mailboxToken, strconv.FormatInt(ownerA.accountID, 10)); got != http.StatusUnauthorized {
		t.Fatalf("retargeted gateway assertion = %d, want 401", got)
	}
	sendPath := "/webapi/v0/messages"
	sendBody := []byte(`{"to":["recipient@example.net"],"subject":"Agent identity","text":"body"}`)
	selectedAgentAccount := strconv.FormatInt(agentAccountID, 10)
	sendToken, err := gatewayassert.SignForMailbox(secret, "octo-server", "octo-user-a", "space-a", selectedAgentAccount, http.MethodPost, sendPath, sendBody, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sendRequest, err := http.NewRequest(http.MethodPost, httpServer.URL+sendPath, bytes.NewReader(sendBody))
	if err != nil {
		t.Fatal(err)
	}
	sendRequest.Header.Set("Authorization", "Bearer "+sendToken)
	sendRequest.Header.Set("X-Octo-Mailbox-ID", selectedAgentAccount)
	sendRequest.Header.Set("Content-Type", "application/json")
	sendResponse, err := http.DefaultClient.Do(sendRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer sendResponse.Body.Close()
	var sent map[string]any
	if err := json.NewDecoder(sendResponse.Body).Decode(&sent); err != nil {
		t.Fatal(err)
	}
	if sendResponse.StatusCode != http.StatusAccepted || sent["senderAddress"] != "agent-a@demo.octo.test" {
		t.Fatalf("selected Agent mailbox send = %d %#v", sendResponse.StatusCode, sent)
	}
	var envelopeFrom string
	if err := store.Pool.QueryRow(ctx,
		`SELECT mail_from FROM queue WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, agentAccountID).Scan(&envelopeFrom); err != nil {
		t.Fatal(err)
	}
	if envelopeFrom != "agent-a@demo.octo.test" {
		t.Fatalf("selected Agent mailbox MAIL FROM = %q", envelopeFrom)
	}
	rawPath := "/webapi/v0/messages/" + sent["messageId"].(string) + "/raw"
	rawToken, err := gatewayassert.SignForMailbox(secret, "octo-server", "octo-user-a", "space-a", selectedAgentAccount, http.MethodGet, rawPath, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := http.NewRequest(http.MethodGet, httpServer.URL+rawPath, nil)
	rawRequest.Header.Set("Authorization", "Bearer "+rawToken)
	rawRequest.Header.Set("X-Octo-Mailbox-ID", selectedAgentAccount)
	rawResponse, err := http.DefaultClient.Do(rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(rawResponse.Body)
	rawResponse.Body.Close()
	if rawResponse.StatusCode != http.StatusOK || !bytes.Contains(raw, []byte("From: agent-a@demo.octo.test")) {
		t.Fatalf("selected Agent mailbox From header = %d %.300q", rawResponse.StatusCode, raw)
	}
	status, _ = request("octo-user-a", "space-b", "/webapi/v0/identity", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("unmapped Space status = %d", status)
	}
	status, _ = request("octo-user-a", "space-a", "/webapi/v0/identity", strconv.FormatInt(ownerB.accountID, 10))
	if status != http.StatusUnauthorized {
		t.Fatalf("cross-owner selected mailbox status = %d", status)
	}
}
