package mailrules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
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
	mustScan(t, store, ctx,
		`INSERT INTO mail_rules
		 (account_id,name,enabled,priority,match_from,match_subject,forward_targets,created_by_principal_id)
		 VALUES ($1,'urgent customers',true,10,'customer@example.net','urgent',$2,$3) RETURNING id`,
		&ruleID, accountID, []string{"triage@example.org", "owner@example.com"}, principalID)

	submitter := &captureSubmitter{}
	authenticator := mustRuleAuthenticator(t)
	processor := &Processor{Pool: store.Pool, Submitter: submitter, RuleMetadata: authenticator}
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
		"X-Octo-Rule-Signature: v1.",
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

	blocked := []struct {
		id   int64
		head string
		code string
	}{
		{102, "Auto-Submitted: no\r\nAuto-Submitted: auto-generated\r\n", "auto_submitted"},
		{105, signedRuleHeaders(t, authenticator, "customer@example.net", "agent@example.com", 999, 3, "<source@example.net>"), "hop_limit"},
		{106, signedRuleHeaders(t, authenticator, "customer@example.net", "agent@example.com", ruleID, 1, "<source@example.net>"), "rule_repeated"},
	}
	for _, test := range blocked {
		message := bytes.Replace(raw, []byte("\r\n\r\n"), []byte("\r\n"+test.head+"\r\n"), 1)
		if err := processor.Process(ctx, accountID, test.id, message); err != nil {
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
	if len(submitter.submissions) != 3 {
		t.Fatalf("blocked submissions = %d, want 3", len(submitter.submissions))
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

func TestConfiguredForwardMessageLimit(t *testing.T) {
	raw := []byte("From: sender@example.net\r\n" +
		"To: agent@example.com\r\n" +
		"Subject: oversized\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		strings.Repeat("x", 65))
	if _, err := parseMessageWithLimit(raw, 64, nil); err == nil {
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

func signedRuleHeaders(t *testing.T, authenticator *rulemetadata.Authenticator, originalFrom, sentBy string, ruleID int64, hop int, messageID string) string {
	t.Helper()
	signature, err := authenticator.Sign(rulemetadata.Metadata{
		OriginalFrom: originalFrom,
		SentBy:       sentBy,
		RuleID:       ruleID,
		Hop:          hop,
		MessageID:    messageID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return "Auto-Submitted: no\r\n" +
		"X-Octo-Original-From: " + originalFrom + "\r\n" +
		"X-Octo-Sent-By: " + sentBy + "\r\n" +
		"X-Octo-Rule-ID: " + decimal(ruleID) + "\r\n" +
		"X-Octo-Rule-Hop: " + strconv.Itoa(hop) + "\r\n" +
		"X-Octo-Rule-Signature: " + signature + "\r\n"
}
