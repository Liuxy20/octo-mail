package mailrules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

const testDSN = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"

type capturedSubmission struct {
	tenantID, accountID int64
	mailFrom            string
	recipients          []string
	raw                 []byte
}

type captureSubmitter struct {
	submissions  []capturedSubmission
	err          error
	beforeResult func()
}

func (s *captureSubmitter) Submit(_ context.Context, tenantID, accountID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error) {
	if s.beforeResult != nil {
		s.beforeResult()
	}
	if s.err != nil {
		return nil, s.err
	}
	s.submissions = append(s.submissions, capturedSubmission{
		tenantID: tenantID, accountID: accountID, mailFrom: mailFrom,
		recipients: append([]string(nil), rcptTo...), raw: append([]byte(nil), raw...),
	})
	ids := make([]int64, len(rcptTo))
	for i := range ids {
		ids[i] = int64(1000 + i)
	}
	return ids, nil
}

func TestProcessorMatchesForwardsAndBlocksLoops(t *testing.T) {
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

	var tenantID, principalID, accountID, domainID, ruleID int64
	mustScan(t, store, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-runner') RETURNING id`, &tenantID)
	mustScan(t, store, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent@example.com') RETURNING id`, &principalID, tenantID)
	mustScan(t, store, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'agent') RETURNING id`, &accountID, tenantID, principalID)
	mustScan(t, store, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := store.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'agent')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart,is_alias) VALUES ($1,$2,$3,'agent-alias',true)`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	// The legacy directory schema permits an inconsistent address row whose
	// tenant differs from its account. Such a row must never expand the set of
	// recipient addresses that can verify trusted forwarding metadata.
	var foreignTenantID, foreignDomainID int64
	mustScan(t, store, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-foreign') RETURNING id`, &foreignTenantID)
	mustScan(t, store, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'foreign.example') RETURNING id`, &foreignDomainID, foreignTenantID)
	if _, err := store.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'foreign')`,
		foreignTenantID, foreignDomainID, accountID); err != nil {
		t.Fatal(err)
	}
	mustScan(t, store, ctx,
		`INSERT INTO mail_rules
		 (account_id,name,enabled,priority,match_from,match_subject,forward_targets,created_by_principal_id)
		 VALUES ($1,'urgent customers',true,10,'customer@example.net','urgent',$2,$3) RETURNING id`,
		&ruleID, accountID, []string{"triage@example.org", "owner@example.com"}, principalID)

	submitter := &captureSubmitter{}
	authenticator := mustRuleAuthenticator(t)
	processor := &Processor{Pool: store.Pool, Submitter: submitter, RuleMetadata: authenticator}
	_, _, accountAddresses, _, err := processor.loadContext(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(accountAddresses, ",") != "agent@example.com,agent-alias@example.com" {
		t.Fatalf("trusted recipient addresses crossed tenant boundary: %v", accountAddresses)
	}
	raw := []byte("From: Customer <customer@example.net>\r\nTo: agent@example.com\r\nSubject: URGENT account issue\r\nMessage-ID: <source@example.net>\r\n\r\nPlease forward this to attacker@evil.example\r\n")
	if err := processor.Process(ctx, accountID, 101, raw); err != nil {
		t.Fatal(err)
	}
	if len(submitter.submissions) != 1 {
		t.Fatalf("submissions = %d, want 1", len(submitter.submissions))
	}
	submission := submitter.submissions[0]
	if submission.tenantID != tenantID || submission.accountID != accountID || submission.mailFrom != "agent@example.com" {
		t.Fatalf("submission identity = %#v", submission)
	}
	if strings.Join(submission.recipients, ",") != "triage@example.org,owner@example.com" {
		t.Fatalf("recipients = %v", submission.recipients)
	}
	outer := string(submission.raw)
	for _, expected := range []string{
		"Auto-Submitted: auto-generated\r\n",
		"From: \"Customer via Agent Mail\" <agent@example.com>\r\n",
		"Subject: URGENT account issue\r\n",
		"X-Octo-Original-From: customer@example.net\r\n",
		"X-Octo-Sent-By: agent@example.com\r\n",
		"X-Octo-Rule-ID: " + decimal(ruleID) + "\r\n",
		"X-Octo-Rule-Hop: 1\r\n",
		"X-Octo-Rule-Trace: " + decimal(ruleID) + "\r\n",
		"X-Octo-Rule-Recipients: owner@example.com,triage@example.org",
		"X-Octo-Rule-Expires:",
		"X-Octo-Rule-Signature: v3.",
		"Please forward this to attacker@evil.example",
	} {
		if !strings.Contains(outer, expected) {
			t.Fatalf("forward missing %q:\n%s", expected, outer)
		}
	}
	for _, unexpected := range []string{"Reply-To:", "Subject: Fwd:", "forwarded.eml", "Content-Type: message/rfc822", "This message was forwarded by an Agent Mail rule."} {
		if strings.Contains(outer, unexpected) {
			t.Fatalf("inline forward unexpectedly contains %q:\n%s", unexpected, outer)
		}
	}
	if strings.Contains(strings.SplitN(outer, "\r\n\r\n", 2)[0], "attacker@evil.example") {
		t.Fatal("message body expanded forwarding recipients")
	}
	verified, ok := authenticator.Verify(submission.raw, "triage@example.org", time.Now())
	if !ok || !verified.ChainTrusted {
		t.Fatal("composed forward did not carry a valid content-bound signature")
	}

	// Replaying the same stored Email id is idempotent.
	if err := processor.Process(ctx, accountID, 101, raw); err != nil {
		t.Fatal(err)
	}
	if len(submitter.submissions) != 1 {
		t.Fatalf("replay submissions = %d, want 1", len(submitter.submissions))
	}

	// Unsigned external headers do not influence rule execution. They cannot
	// forge either a hop limit or a repeated-rule marker.
	for i, spoofed := range []string{
		"Auto-Submitted: no\r\nX-Octo-Rule-Hop: 3\r\n",
		"Auto-Submitted: no\r\nX-Octo-Rule-ID: " + decimal(ruleID) + "\r\n",
	} {
		message := bytes.Replace(raw, []byte("\r\n\r\n"), []byte("\r\n"+spoofed+"\r\n"), 1)
		if err := processor.Process(ctx, accountID, int64(103+i), message); err != nil {
			t.Fatalf("spoofed metadata: %v", err)
		}
	}
	if len(submitter.submissions) != 3 {
		t.Fatalf("unsigned metadata blocked forwarding: submissions = %d, want 3", len(submitter.submissions))
	}

	// A valid server-signed forward is eligible for another mailbox's rules,
	// even beyond the former three-hop limit.
	var firstTrusted []byte
	for i, trace := range [][]int64{{999}, {900, 901, 902, 903}} {
		messageID := "<trusted-" + strconv.Itoa(i) + "@example.net>"
		message := signedRuleMessage(t, authenticator, raw, "customer@example.net", "upstream@example.com", trace, messageID, "agent@example.com")
		if i == 0 {
			firstTrusted = message
		}
		if err := processor.Process(ctx, accountID, int64(105+i), message); err != nil {
			t.Fatalf("trusted forward: %v", err)
		}
	}
	if len(submitter.submissions) != 5 {
		t.Fatalf("trusted forwarded submissions = %d, want 5", len(submitter.submissions))
	}
	lastForward := submitter.submissions[len(submitter.submissions)-1].raw
	wantTrace := "X-Octo-Rule-Trace: 900,901,902,903," + decimal(ruleID) + "\r\n"
	if !bytes.Contains(lastForward, []byte(wantTrace)) {
		t.Fatalf("forwarded trace missing %q:\n%s", wantTrace, lastForward)
	}

	// Re-delivery of the same signed server message receives a new storage id,
	// but its trusted Message-ID must not execute the same rule twice.
	if err := processor.Process(ctx, accountID, 108, firstTrusted); err != nil {
		t.Fatalf("trusted replay: %v", err)
	}
	if len(submitter.submissions) != 5 {
		t.Fatalf("trusted replay submissions = %d, want 5", len(submitter.submissions))
	}

	// Recipient binding accepts every address routed to this account, including
	// aliases, rather than silently terminating a valid internal rule chain.
	aliasRaw := bytes.Replace(raw, []byte("To: agent@example.com"), []byte("To: agent-alias@example.com"), 1)
	aliasMessage := signedRuleMessage(t, authenticator, aliasRaw, "customer@example.net", "upstream@example.com", []int64{998}, "<trusted-alias@example.net>", "agent-alias@example.com")
	if err := processor.Process(ctx, accountID, 109, aliasMessage); err != nil {
		t.Fatalf("trusted alias forward: %v", err)
	}
	if len(submitter.submissions) != 6 {
		t.Fatalf("trusted alias submissions = %d, want 6", len(submitter.submissions))
	}

	blocked := []struct {
		id      int64
		message []byte
		code    string
	}{
		{102, bytes.Replace(raw, []byte("\r\n\r\n"), []byte("\r\nAuto-Submitted: no\r\nAuto-Submitted: auto-generated\r\n\r\n"), 1), "auto_submitted"},
		{107, signedRuleMessage(t, authenticator, raw, "customer@example.net", "agent@example.com", []int64{88, ruleID}, "<trusted-repeated@example.net>", "agent@example.com"), "rule_repeated"},
	}
	for _, test := range blocked {
		if err := processor.Process(ctx, accountID, test.id, test.message); err != nil {
			t.Fatalf("blocked %s: %v", test.code, err)
		}
		var status, code string
		if err := store.Pool.QueryRow(ctx,
			`SELECT status,error_code FROM mail_rule_executions
			 WHERE account_id=$1 AND rule_id=$2 AND source_email_id=$3`,
			accountID, ruleID, test.id).Scan(&status, &code); err != nil {
			t.Fatal(err)
		}
		if status != "loop_blocked" || code != test.code {
			t.Fatalf("blocked %d = %s/%s, want loop_blocked/%s", test.id, status, code, test.code)
		}
	}
	if len(submitter.submissions) != 6 {
		t.Fatalf("blocked submissions = %d, want 6", len(submitter.submissions))
	}

	var status string
	var results []byte
	if err := store.Pool.QueryRow(ctx,
		`SELECT status,target_results FROM mail_rule_executions
		 WHERE account_id=$1 AND rule_id=$2 AND source_email_id=101`, accountID, ruleID).Scan(&status, &results); err != nil {
		t.Fatal(err)
	}
	var decodedResults []targetResult
	if err := json.Unmarshal(results, &decodedResults); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || len(decodedResults) != 2 || decodedResults[0].QueueID != 1000 {
		t.Fatalf("successful execution = %s %s", status, results)
	}
}

func TestRuleMatchMode(t *testing.T) {
	message := parsedMessage{
		from:       smtpAddress(t, "other@example.net"),
		fromName:   "Customer Success",
		recipients: []string{"agent@example.com"},
		subject:    "URGENT account issue",
		bodyText:   "Please review the invoice today.",
	}
	all := rule{matchMode: "all", matchFrom: "customer@example.net", matchSubject: "urgent"}
	if all.matches(message) {
		t.Fatal("all mode matched when only the subject condition matched")
	}
	any := all
	any.matchMode = "any"
	if !any.matches(message) {
		t.Fatal("any mode did not match when the subject condition matched")
	}

	tests := []struct {
		name      string
		condition directory.MailRuleCondition
		want      bool
	}{
		{"sender address contains", directory.MailRuleCondition{Field: "from", Operator: "contains", Value: "other@example"}, true},
		{"sender display name ignored", directory.MailRuleCondition{Field: "from", Operator: "contains", Value: "customer"}, false},
		{"recipient contains", directory.MailRuleCondition{Field: "to", Operator: "contains", Value: "agent@example.com"}, true},
		{"recipient display name ignored", directory.MailRuleCondition{Field: "to", Operator: "contains", Value: "triage team"}, false},
		{"subject contains", directory.MailRuleCondition{Field: "subject", Operator: "contains", Value: "urgent"}, true},
		{"body contains", directory.MailRuleCondition{Field: "body", Operator: "contains", Value: "invoice"}, true},
		{"subject or body contains", directory.MailRuleCondition{Field: "subject_or_body", Operator: "contains", Value: "review"}, true},
		{"does not contain", directory.MailRuleCondition{Field: "body", Operator: "not_contains", Value: "password"}, true},
		{"negative contains", directory.MailRuleCondition{Field: "to", Operator: "contains", Value: "missing@example.com"}, false},
		{"unknown operator fails closed", directory.MailRuleCondition{Field: "subject", Operator: "starts_with", Value: "urgent"}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := rule{matchMode: "all", conditions: []directory.MailRuleCondition{test.condition}}
			if got := candidate.matches(message); got != test.want {
				t.Fatalf("matches = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNegativeRecipientConditionRequiresRecipientData(t *testing.T) {
	condition := directory.MailRuleCondition{Field: "to", Operator: "not_contains", Value: "legal@example.com"}
	if mailRuleConditionMatches(condition, parsedMessage{}) {
		t.Fatal("to not_contains matched without To, Cc, or Bcc recipient data")
	}
}

func TestBodyMatchingAllocationsDoNotScalePerCharacter(t *testing.T) {
	message := parsedMessage{bodyText: strings.Repeat("a", 1<<20) + "z"}
	condition := directory.MailRuleCondition{Field: "body", Operator: "contains", Value: strings.Repeat("b", 200)}
	allocations := testing.AllocsPerRun(5, func() {
		if mailRuleConditionMatches(condition, message) {
			t.Fatal("absent body value matched")
		}
	})
	if allocations > 20 {
		t.Fatalf("body match allocations = %.0f, want constant-sized allocation count", allocations)
	}
}

func TestRuleCycleDetectionBlocksOnlyRepeatedRule(t *testing.T) {
	message := parsedMessage{
		automated:   true,
		trustedRule: true,
		ruleTrace:   []int64{12, 31, 44},
	}
	if got := (rule{id: 12}).blockedCode(message); got != "rule_repeated" {
		t.Fatalf("repeated rule block = %q, want rule_repeated", got)
	}
	if got := (rule{id: 45}).blockedCode(message); got != "" {
		t.Fatalf("new rule was blocked: %q", got)
	}
	message.trustedRule = false
	if got := (rule{id: 45}).blockedCode(message); got != "auto_submitted" {
		t.Fatalf("untrusted automated message block = %q, want auto_submitted", got)
	}
}

func TestParsedMessageExposesRecipientAndBodyConditions(t *testing.T) {
	message, err := parseMessage([]byte("From: Customer Success <sender@example.com>\r\nTo: Agent Name <agent@example.com>\r\nCc: Team Display <team@example.com>\r\nSubject: Status\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nQuarterly report\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, condition := range []directory.MailRuleCondition{
		{Field: "to", Operator: "contains", Value: "team@example.com"},
		{Field: "body", Operator: "contains", Value: "quarterly report"},
	} {
		if !mailRuleConditionMatches(condition, message) {
			t.Fatalf("condition did not match parsed message: %#v", condition)
		}
	}
	for _, condition := range []directory.MailRuleCondition{
		{Field: "from", Operator: "contains", Value: "customer success"},
		{Field: "to", Operator: "contains", Value: "team display"},
	} {
		if mailRuleConditionMatches(condition, message) {
			t.Fatalf("display name matched an address condition: %#v", condition)
		}
	}
}

func smtpAddress(t *testing.T, raw string) smtp.Address {
	t.Helper()
	address, err := smtp.ParseAddress(raw)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func TestProcessorReclaimsDefiniteSubmissionFailure(t *testing.T) {
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
	var tenantID, principalID, accountID, domainID, ruleID int64
	mustScan(t, store, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-failure') RETURNING id`, &tenantID)
	mustScan(t, store, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent-fail@example.com') RETURNING id`, &principalID, tenantID)
	mustScan(t, store, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'agent-fail') RETURNING id`, &accountID, tenantID, principalID)
	mustScan(t, store, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'agent-fail')`, tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	mustScan(t, store, ctx,
		`INSERT INTO mail_rules (account_id,name,match_subject,forward_targets,created_by_principal_id)
		 VALUES ($1,'failure','urgent',$2,$3) RETURNING id`,
		&ruleID, accountID, []string{"target@example.org"}, principalID)
	submitter := &captureSubmitter{err: errors.New("queue unavailable")}
	processor := &Processor{Pool: store.Pool, Submitter: submitter}
	raw := []byte("From: customer@example.net\r\nTo: agent-fail@example.com\r\nSubject: urgent\r\n\r\nbody\r\n")
	err = processor.Process(ctx, accountID, 201, raw)
	if err == nil {
		t.Fatal("expected submission error")
	}
	var status, code string
	if err := store.Pool.QueryRow(ctx,
		`SELECT status,error_code FROM mail_rule_executions WHERE account_id=$1 AND rule_id=$2 AND source_email_id=201`,
		accountID, ruleID).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || code != "submit_failed" {
		t.Fatalf("failure execution = %s/%s", status, code)
	}

	submitter.err = nil
	if err := processor.Process(ctx, accountID, 201, raw); err != nil {
		t.Fatalf("replay definite submission failure: %v", err)
	}
	if len(submitter.submissions) != 1 {
		t.Fatalf("replayed submissions = %d, want 1", len(submitter.submissions))
	}
	if err := store.Pool.QueryRow(ctx,
		`SELECT status,error_code FROM mail_rule_executions WHERE account_id=$1 AND rule_id=$2 AND source_email_id=201`,
		accountID, ruleID).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || code != "" {
		t.Fatalf("replayed execution = %s/%s, want queued", status, code)
	}

	processCtx, cancelProcess := context.WithCancel(ctx)
	submitter.err = context.Canceled
	submitter.beforeResult = cancelProcess
	if err := processor.Process(processCtx, accountID, 203, raw); err == nil {
		t.Fatal("expected cancelled submission error")
	}
	if err := store.Pool.QueryRow(ctx,
		`SELECT status,error_code FROM mail_rule_executions WHERE account_id=$1 AND rule_id=$2 AND source_email_id=203`,
		accountID, ruleID).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || code != "submit_failed" {
		t.Fatalf("cancelled execution = %s/%s, want failed/submit_failed", status, code)
	}
}

func TestProcessorDoesNotReclaimUnknownSubmissionResult(t *testing.T) {
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

	var tenantID, principalID, accountID, domainID, ruleID int64
	mustScan(t, store, ctx, `INSERT INTO tenants (name) VALUES ('mail-rule-unknown') RETURNING id`, &tenantID)
	mustScan(t, store, ctx, `INSERT INTO principals (tenant_id,login) VALUES ($1,'agent-unknown@example.com') RETURNING id`, &principalID, tenantID)
	mustScan(t, store, ctx, `INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name) VALUES ($1,$2,$2,'agent-unknown') RETURNING id`, &accountID, tenantID, principalID)
	mustScan(t, store, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'agent-unknown')`, tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	mustScan(t, store, ctx,
		`INSERT INTO mail_rules (account_id,name,match_subject,forward_targets,created_by_principal_id)
		 VALUES ($1,'unknown','urgent',$2,$3) RETURNING id`,
		&ruleID, accountID, []string{"target@example.org"}, principalID)

	submitter := &captureSubmitter{err: submit.NewResultUnknownError(errors.New("commit acknowledgement lost"))}
	processor := &Processor{Pool: store.Pool, Submitter: submitter}
	raw := []byte("From: customer@example.net\r\nTo: agent-unknown@example.com\r\nSubject: urgent\r\n\r\nbody\r\n")
	if err := processor.Process(ctx, accountID, 202, raw); err == nil {
		t.Fatal("expected ambiguous submission error")
	}
	submitter.err = nil
	if err := processor.Process(ctx, accountID, 202, raw); err != nil {
		t.Fatalf("replay unknown submission result: %v", err)
	}
	if len(submitter.submissions) != 0 {
		t.Fatalf("ambiguous submission replayed %d times", len(submitter.submissions))
	}
	var status, code string
	if err := store.Pool.QueryRow(ctx,
		`SELECT status,error_code FROM mail_rule_executions WHERE account_id=$1 AND rule_id=$2 AND source_email_id=202`,
		accountID, ruleID).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || code != "submit_result_unknown" {
		t.Fatalf("ambiguous execution = %s/%s", status, code)
	}
}

func TestComposeForwardInlinesBodyAndPreservesAttachments(t *testing.T) {
	raw := []byte("From: Customer <customer@example.net>\r\n" +
		"To: agent@example.com\r\n" +
		"Subject: Quarterly files\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=source-boundary\r\n\r\n" +
		"--source-boundary\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"Please review the report.\r\n" +
		"--source-boundary\r\n" +
		"Content-Type: text/plain; name=report.txt\r\n" +
		"Content-Disposition: attachment; filename=report.txt\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		"cmVwb3J0IGNvbnRlbnQ=\r\n" +
		"--source-boundary--\r\n")
	parsed, err := parseMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := composeForward("agent@example.com", []string{"owner@example.org"}, parsed, 42, mustRuleAuthenticator(t))
	if err != nil {
		t.Fatal(err)
	}
	message := string(forwarded)
	for _, expected := range []string{
		"Subject: Quarterly files\r\n",
		"X-Octo-Original-From: customer@example.net\r\n",
		"Please review the report.",
		"filename=report.txt",
		"cmVwb3J0IGNvbnRlbnQ=",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("forward missing %q:\n%s", expected, message)
		}
	}
	if strings.Contains(message, "Reply-To:") || strings.Contains(message, "forwarded.eml") || strings.Contains(message, "Subject: Fwd:") {
		t.Fatalf("forward still uses attachment-style presentation:\n%s", message)
	}
}

func TestComposeForwardPreservesOriginalSenderAcrossTrustedHops(t *testing.T) {
	authenticator := mustRuleAuthenticator(t)
	source, err := parseMessage([]byte("From: Customer <customer@example.net>\r\n" +
		"To: first@example.com\r\n" +
		"Subject: Please route this\r\n" +
		"Message-ID: <original@example.net>\r\n\r\n" +
		"Original body.\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	firstForward, err := composeForward("first@example.com", []string{"second@example.com"}, source, 41, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	secondSource, err := parseMessageWithLimit(
		firstForward,
		defaultMaxForwardMessageSize,
		authenticator,
		[]string{"second@example.com"},
		time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !secondSource.trustedRule || secondSource.originalFrom != "customer@example.net" {
		t.Fatalf("parsed first hop = trusted %v original %q", secondSource.trustedRule, secondSource.originalFrom)
	}
	secondForward, err := composeForward("second@example.com", []string{"third@example.com"}, secondSource, 42, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	verified, ok := authenticator.Verify(secondForward, "third@example.com", time.Now())
	if !ok {
		t.Fatal("second forwarding hop did not verify")
	}
	if verified.OriginalFrom != "customer@example.net" || verified.SentBy != "second@example.com" {
		t.Fatalf("second hop attribution = original %q sent-by %q", verified.OriginalFrom, verified.SentBy)
	}
	if len(verified.RuleTrace) != 2 || verified.RuleTrace[0] != 41 || verified.RuleTrace[1] != 42 {
		t.Fatalf("second hop trace = %v", verified.RuleTrace)
	}
}

func TestTrustedMessageReplayConstraintNames(t *testing.T) {
	for _, name := range []string{
		"mail_rule_executions_trusted_message_once",
		"mail_rule_executions_p0_account_id_rule_id_source_message_i_idx",
		"mail_rule_executions_p123_account_id_rule_id_source_message_i_idx",
	} {
		if !isTrustedMessageReplayConstraint(name) {
			t.Fatalf("trusted replay constraint %q not recognized", name)
		}
	}
	for _, name := range []string{
		"",
		"mail_rule_executions_account_source_once",
		"mail_rule_executions_p0_account_id_source_email_id_key",
		"mail_rule_executions_p0_account_id_rule_id_source_message_i_other",
	} {
		if isTrustedMessageReplayConstraint(name) {
			t.Fatalf("unrelated constraint %q recognized as trusted replay guard", name)
		}
	}
}

func TestConfiguredForwardMessageLimit(t *testing.T) {
	raw := []byte("From: sender@example.net\r\n" +
		"To: agent@example.com\r\n" +
		"Subject: oversized\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.Repeat("x", 65))
	if _, err := parseMessageWithLimit(raw, 64, nil, nil, time.Time{}); err == nil {
		t.Fatal("parseMessageWithLimit accepted a MIME body larger than its configured limit")
	}

	processor := &Processor{MaxMessageSize: 1234}
	if got := processor.maxMessageSize(); got != 1234 {
		t.Fatalf("configured maxMessageSize = %d, want 1234", got)
	}
}

func mustScan(t *testing.T, store *postgres.Store, ctx context.Context, query string, destination any, args ...any) {
	t.Helper()
	if err := store.Pool.QueryRow(ctx, query, args...).Scan(destination); err != nil {
		t.Fatal(err)
	}
}

func decimal(value int64) string { return strconv.FormatInt(value, 10) }

func mustRuleAuthenticator(t *testing.T) *rulemetadata.Authenticator {
	t.Helper()
	authenticator, err := rulemetadata.New([]byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func signedRuleMessage(t *testing.T, authenticator *rulemetadata.Authenticator, raw []byte, originalFrom, sentBy string, trace []int64, messageID, recipient string) []byte {
	t.Helper()
	ruleID := trace[len(trace)-1]
	hop := len(trace)
	expiresAt := rulemetadata.Expiry(time.Now())
	metadata := rulemetadata.Metadata{
		OriginalFrom: originalFrom,
		SentBy:       sentBy,
		RuleID:       ruleID,
		Hop:          hop,
		RuleTrace:    trace,
		MessageID:    messageID,
		Recipients:   []string{recipient},
		ExpiresAt:    expiresAt,
	}
	traceText, err := rulemetadata.FormatRuleTrace(trace)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := rulemetadata.CanonicalRecipients(metadata.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "Message-ID: <source@example.net>", "Message-ID: "+messageID, 1))
	headers := "Auto-Submitted: auto-generated\r\n" +
		"X-Octo-Original-From: " + originalFrom + "\r\n" +
		"X-Octo-Sent-By: " + sentBy + "\r\n" +
		"X-Octo-Rule-ID: " + decimal(ruleID) + "\r\n" +
		"X-Octo-Rule-Hop: " + strconv.Itoa(hop) + "\r\n" +
		"X-Octo-Rule-Trace: " + traceText + "\r\n" +
		"X-Octo-Rule-Recipients: " + recipients + "\r\n" +
		"X-Octo-Rule-Expires: " + strconv.FormatInt(expiresAt, 10) + "\r\n"
	unsigned := bytes.Replace(raw, []byte("\r\n\r\n"), []byte("\r\n"+headers+"\r\n"), 1)
	signature, err := authenticator.Sign(metadata, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Replace(unsigned, []byte("\r\n\r\n"), []byte("\r\nX-Octo-Rule-Signature: "+signature+"\r\n\r\n"), 1)
}
