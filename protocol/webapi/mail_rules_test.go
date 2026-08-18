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

	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
)

func TestAgentMailRuleOwnerCRUDAndIsolation(t *testing.T) {
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

	var tenantID, ownerID, ownerAccountID, mailboxPrincipalID, mailboxID, otherID, otherAccountID, domainID int64
	scan(t, s, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-owner') RETURNING id`, &tenantID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@example.com') RETURNING id`, &ownerID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'owner') RETURNING id`, &ownerAccountID, tenantID, ownerID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'rules@example.com') RETURNING id`, &mailboxPrincipalID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$3,'rules') RETURNING id`, &mailboxID, tenantID, mailboxPrincipalID, ownerID)
	scan(t, s, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'other@example.com') RETURNING id`, &otherID, tenantID)
	scan(t, s, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'other') RETURNING id`, &otherAccountID, tenantID, otherID)
	scan(t, s, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES
		 ($1,$2,$3,'owner'),($1,$2,$4,'rules'),($1,$2,$5,'other')`,
		tenantID, domainID, ownerAccountID, mailboxID, otherAccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO agent_mailbox_registrations (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,'space-a')`, tenantID, mailboxID, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','octo-owner','space-a',$1,$2,$3),
		        ('octo-server','octo-other','space-a',$1,$4,$5)`,
		tenantID, ownerID, ownerAccountID, otherID, otherAccountID); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	if err := dir.SetPassword(ctx, "owner@example.com", "owner-pw"); err != nil {
		t.Fatal(err)
	}
	if err := dir.SetPassword(ctx, "other@example.com", "other-pw"); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := dir.IssueAPIKey(ctx, "owner@example.com", "owner automation")
	if err != nil {
		t.Fatal(err)
	}

	gatewaySecret := []byte(strings.Repeat("g", 32))
	hs := httptest.NewServer((&webapi.Server{Dir: dir, GatewaySecret: gatewaySecret}).Handler())
	defer hs.Close()
	type credentials struct{ login, password, bearer, gatewaySubject, spaceID string }
	do := func(method, path string, body any, credentials credentials) (int, map[string]any) {
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
		if credentials.gatewaySubject != "" {
			token, err := gatewayassert.Sign(gatewaySecret, "octo-server", credentials.gatewaySubject, credentials.spaceID, method, path, requestBody, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
		} else if credentials.bearer != "" {
			req.Header.Set("Authorization", "Bearer "+credentials.bearer)
		} else {
			req.SetBasicAuth(credentials.login, credentials.password)
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

	ownerAuth := credentials{gatewaySubject: "octo-owner", spaceID: "space-a"}
	otherAuth := credentials{gatewaySubject: "octo-other", spaceID: "space-a"}
	base := "/webapi/v0/agent-mailboxes/" + strconv.FormatInt(mailboxID, 10) + "/rules"
	status, created := do(http.MethodPost, base, map[string]any{
		"name": "Priority customers", "priority": 20,
		"matchMode": "any",
		"conditions": []map[string]any{
			{"field": "from", "operator": "contains", "value": "customer@example.net"},
			{"field": "body", "operator": "not_contains", "value": "password"},
		},
		"matchFrom": "customer@EXAMPLE.NET", "matchSubject": "urgent",
		"forwardTargets": []string{"triage@example.net", "triage@EXAMPLE.NET", "owner@example.com"},
	}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create rule = %d %#v", status, created)
	}
	if created["enabled"] != true || created["matchMode"] != "any" || created["matchFrom"] != "customer@example.net" {
		t.Fatalf("created rule normalization = %#v", created)
	}
	if conditions, ok := created["conditions"].([]any); !ok || len(conditions) != 2 {
		t.Fatalf("created conditions = %#v", created["conditions"])
	}
	if targets, ok := created["forwardTargets"].([]any); !ok || len(targets) != 2 {
		t.Fatalf("created targets = %#v", created["forwardTargets"])
	}
	ruleID := created["id"].(string)

	status, listed := do(http.MethodGet, base, nil, ownerAuth)
	if status != http.StatusOK || len(listed["rules"].([]any)) != 1 {
		t.Fatalf("list rules = %d %#v", status, listed)
	}
	status, executions := do(http.MethodGet, "/webapi/v0/agent-mailboxes/"+strconv.FormatInt(mailboxID, 10)+"/rule-executions", nil, ownerAuth)
	if status != http.StatusOK || len(executions["executions"].([]any)) != 0 {
		t.Fatalf("list executions = %d %#v", status, executions)
	}

	status, denied := do(http.MethodPost, base, map[string]any{
		"name": "denied", "matchSubject": "x", "forwardTargets": []string{"x@example.net"},
	}, otherAuth)
	if status != http.StatusForbidden || denied["error"].(map[string]any)["code"] != "mailbox_not_owned" {
		t.Fatalf("cross-owner create = %d %#v", status, denied)
	}
	status, denied = do(http.MethodPatch, base+"/"+ruleID, map[string]any{"enabled": false}, credentials{bearer: ownerKey})
	if status != http.StatusForbidden || denied["error"].(map[string]any)["code"] != "human_owner_required" {
		t.Fatalf("API-key mutation = %d %#v", status, denied)
	}

	status, updated := do(http.MethodPatch, base+"/"+ruleID, map[string]any{
		"enabled": false, "matchSubject": "billing",
	}, ownerAuth)
	if status != http.StatusOK || updated["enabled"] != false || updated["matchSubject"] != "billing" {
		t.Fatalf("update rule = %d %#v", status, updated)
	}
	updatedConditions, ok := updated["conditions"].([]any)
	if !ok || len(updatedConditions) != 3 {
		t.Fatalf("legacy PATCH conditions = %#v", updated["conditions"])
	}
	wantConditions := map[string]bool{
		"from/contains/customer@example.net": false,
		"body/not_contains/password":         false,
		"subject/contains/billing":           false,
	}
	for _, value := range updatedConditions {
		condition, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("legacy PATCH condition = %#v", value)
		}
		key := condition["field"].(string) + "/" + condition["operator"].(string) + "/" + condition["value"].(string)
		if _, expected := wantConditions[key]; expected {
			wantConditions[key] = true
		}
	}
	for condition, found := range wantConditions {
		if !found {
			t.Fatalf("legacy PATCH dropped condition %q: %#v", condition, updatedConditions)
		}
	}
	status, invalid := do(http.MethodPost, base, map[string]any{
		"name": "invalid", "forwardTargets": []string{"x@example.net"},
	}, ownerAuth)
	if status != http.StatusBadRequest || invalid["error"].(map[string]any)["code"] != "invalid_rule" {
		t.Fatalf("invalid rule = %d %#v", status, invalid)
	}
	status, invalid = do(http.MethodPost, base, map[string]any{
		"name": "invalid mode", "matchMode": "sometimes", "matchSubject": "x", "forwardTargets": []string{"x@example.net"},
	}, ownerAuth)
	if status != http.StatusBadRequest || invalid["error"].(map[string]any)["code"] != "invalid_rule" {
		t.Fatalf("invalid match mode = %d %#v", status, invalid)
	}
	status, invalid = do(http.MethodPost, base, map[string]any{
		"name": "invalid condition", "conditions": []map[string]any{{"field": "headers", "operator": "contains", "value": "x"}},
		"forwardTargets": []string{"x@example.net"},
	}, ownerAuth)
	if status != http.StatusBadRequest || invalid["error"].(map[string]any)["code"] != "invalid_rule" {
		t.Fatalf("invalid condition = %d %#v", status, invalid)
	}
	status, normalizedSenderRule := do(http.MethodPost, base, map[string]any{
		"name": "normalized sender", "conditions": []map[string]any{{
			"field": "from", "operator": "equals", "value": "Customer <customer@EXAMPLE.NET>",
		}},
		"forwardTargets": []string{"x@example.net"},
	}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create normalized sender rule = %d %#v", status, normalizedSenderRule)
	}
	normalizedConditions, ok := normalizedSenderRule["conditions"].([]any)
	if !ok || len(normalizedConditions) != 1 || normalizedConditions[0].(map[string]any)["value"] != "customer@example.net" {
		t.Fatalf("normalized sender conditions = %#v", normalizedSenderRule["conditions"])
	}
	status, invalid = do(http.MethodPost, base, map[string]any{
		"name": "invalid sender", "conditions": []map[string]any{{
			"field": "from", "operator": "equals", "value": "not an address",
		}},
		"forwardTargets": []string{"x@example.net"},
	}, ownerAuth)
	if status != http.StatusBadRequest || invalid["error"].(map[string]any)["code"] != "invalid_rule" {
		t.Fatalf("invalid sender equality = %d %#v", status, invalid)
	}
	status, _ = do(http.MethodDelete, base+"/"+normalizedSenderRule["id"].(string), nil, ownerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("delete normalized sender rule = %d", status)
	}
	status, _ = do(http.MethodDelete, base+"/"+ruleID, nil, ownerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("delete rule = %d", status)
	}
	status, listed = do(http.MethodGet, base, nil, ownerAuth)
	if status != http.StatusOK || len(listed["rules"].([]any)) != 0 {
		t.Fatalf("list after delete = %d %#v", status, listed)
	}

	// Execution history is audit data and must survive later rule deletion.
	// Insert a representative completed row directly because the post-storage
	// runner is implemented in the next slice.
	var auditRuleID int64
	status, recreated := do(http.MethodPost, base, map[string]any{
		"name": "audited", "matchSubject": "audit", "forwardTargets": []string{"audit@example.net"},
	}, ownerAuth)
	if status != http.StatusCreated {
		t.Fatalf("create audited rule = %d %#v", status, recreated)
	}
	auditRuleID, err = strconv.ParseInt(recreated["id"].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO mail_rule_executions
		 (account_id,rule_id,source_email_id,status,target_results,completed_at)
		 VALUES ($1,$2,123,'queued','[{"address":"audit@example.net","status":"queued"}]',now())`,
		mailboxID, auditRuleID); err != nil {
		t.Fatal(err)
	}
	status, _ = do(http.MethodDelete, base+"/"+strconv.FormatInt(auditRuleID, 10), nil, ownerAuth)
	if status != http.StatusNoContent {
		t.Fatalf("delete audited rule = %d", status)
	}
	status, executions = do(http.MethodGet, "/webapi/v0/agent-mailboxes/"+strconv.FormatInt(mailboxID, 10)+"/rule-executions", nil, ownerAuth)
	if status != http.StatusOK || len(executions["executions"].([]any)) != 1 {
		t.Fatalf("audit after rule deletion = %d %#v", status, executions)
	}
}
