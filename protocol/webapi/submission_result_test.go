package webapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/protocol/webapi"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/Mininglamp-OSS/octo-mail/storage/postgres"
	"github.com/mjl-/mox/smtp"
)

type resultUnknownSubmitter struct {
	calls atomic.Int32
}

func (s *resultUnknownSubmitter) SubmitForMessage(context.Context, int64, int64, int64, string, []string, []byte) ([]int64, error) {
	s.calls.Add(1)
	return nil, submit.NewResultUnknownError(errors.New("commit acknowledgement lost"))
}

type committedResultUnknownSubmitter struct {
	inner *submit.Submitter
	calls atomic.Int32
}

func (s *committedResultUnknownSubmitter) SubmitForMessage(ctx context.Context, tenantID, accountID, messageID int64, mailFrom string, rcptTo []string, raw []byte) ([]int64, error) {
	s.calls.Add(1)
	if _, err := s.inner.SubmitForMessage(ctx, tenantID, accountID, messageID, mailFrom, rcptTo, raw); err != nil {
		return nil, err
	}
	return nil, submit.NewResultUnknownError(errors.New("commit succeeded but acknowledgement was lost"))
}

func TestUnknownSubmissionPreservesSentAndDraftClaims(t *testing.T) {
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

	var tenantID, accountID, domainID int64
	scan(t, db, ctx, `INSERT INTO tenants (name) VALUES ('unknown-submit') RETURNING id`, &tenantID)
	scan(t, db, ctx, `INSERT INTO accounts (tenant_id,name) VALUES ($1,'sender') RETURNING id`, &accountID, tenantID)
	scan(t, db, ctx, `INSERT INTO domains (tenant_id,domain) VALUES ($1,'example.com') RETURNING id`, &domainID, tenantID)
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'sender')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,'sender@example.com')`, tenantID); err != nil {
		t.Fatal(err)
	}
	dir := db.NewDirectory()
	if err := dir.SetPassword(ctx, "sender@example.com", "pw"); err != nil {
		t.Fatal(err)
	}
	address, _ := smtp.ParseAddress("sender@example.com")
	target, err := dir.ResolveInbound(ctx, address.Path())
	if err != nil {
		t.Fatal(err)
	}
	source := &store.Message{}
	if _, err := target.Deliver(ctx, source, mem("From: customer@example.net\r\nTo: sender@example.com\r\nSubject: source\r\nMessage-ID: <source@example.net>\r\n\r\nhello\r\n")); err != nil {
		t.Fatal(err)
	}
	sourceID := "E" + strconv.FormatInt(source.EffectiveEmailID(), 10)

	unknown := &resultUnknownSubmitter{}
	api := &webapi.Server{Dir: dir, Submission: unknown}
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	request := func(method, path, body string) (int, map[string]any) {
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("sender@example.com", "pw")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		result := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("decode response: %v (%s)", err, raw)
			}
		}
		return resp.StatusCode, result
	}

	for _, write := range []struct {
		name, path, body string
	}{
		{"send", "/webapi/v0/messages", `{"to":["person@example.net"],"subject":"unknown send","text":"body"}`},
		{"reply", "/webapi/v0/messages/" + sourceID + "/reply", `{"text":"unknown reply"}`},
		{"forward", "/webapi/v0/messages/" + sourceID + "/forward", `{"to":["person@example.net"],"text":"unknown forward"}`},
	} {
		t.Run(write.name, func(t *testing.T) {
			status, result := request(http.MethodPost, write.path, write.body)
			if status != http.StatusConflict || result["error"].(map[string]any)["code"] != "submission_result_unknown" {
				t.Fatalf("unknown %s = %d %#v", write.name, status, result)
			}
		})
	}

	status, draft := request(http.MethodPost, "/webapi/v0/drafts", `{"to":["person@example.net"],"subject":"unknown draft","text":"body"}`)
	if status != http.StatusCreated {
		t.Fatalf("create Draft = %d %#v", status, draft)
	}
	draftID := draft["id"].(string)
	status, result := request(http.MethodPost, "/webapi/v0/drafts/"+draftID+"/send", "")
	if status != http.StatusConflict || result["error"].(map[string]any)["code"] != "draft_send_result_unknown" {
		t.Fatalf("unknown Draft send = %d %#v", status, result)
	}
	callsAfterUnknown := unknown.calls.Load()
	status, result = request(http.MethodPost, "/webapi/v0/drafts/"+draftID+"/send", "")
	if status != http.StatusConflict || result["error"].(map[string]any)["code"] != "draft_send_result_unknown" {
		t.Fatalf("repeated unknown Draft send = %d %#v", status, result)
	}
	if unknown.calls.Load() != callsAfterUnknown {
		t.Fatalf("unknown Draft was submitted again: calls %d -> %d", callsAfterUnknown, unknown.calls.Load())
	}

	var sent, drafts, queueRows, processingClaims int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE mb.su_sent), count(*) FILTER (WHERE mb.name='Drafts')
		 FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged`, accountID).Scan(&sent, &drafts); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM queue WHERE account_id=$1`, accountID).Scan(&queueRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM draft_send_claims WHERE account_id=$1 AND status='processing'`, accountID).Scan(&processingClaims); err != nil {
		t.Fatal(err)
	}
	if sent != 4 || drafts != 1 || queueRows != 0 || processingClaims != 1 {
		t.Fatalf("unknown result evidence sent=%d drafts=%d queue=%d claims=%d, want 4/1/0/1", sent, drafts, queueRows, processingClaims)
	}

	// Exercise the other half of an ambiguous COMMIT: PostgreSQL accepted the
	// queue transaction, but the caller lost the acknowledgement. Evidence and
	// the processing claim must remain, and a retry must not submit again.
	committedUnknown := &committedResultUnknownSubmitter{
		inner: &submit.Submitter{Pool: db.Pool, Blob: bs},
	}
	api.Submission = committedUnknown
	status, committedDraft := request(http.MethodPost, "/webapi/v0/drafts", `{"to":["committed@example.net"],"subject":"committed unknown","text":"body"}`)
	if status != http.StatusCreated {
		t.Fatalf("create committed-unknown Draft = %d %#v", status, committedDraft)
	}
	committedDraftID := committedDraft["id"].(string)
	status, result = request(http.MethodPost, "/webapi/v0/drafts/"+committedDraftID+"/send", "")
	if status != http.StatusConflict || result["error"].(map[string]any)["code"] != "draft_send_result_unknown" {
		t.Fatalf("committed unknown Draft send = %d %#v", status, result)
	}
	status, result = request(http.MethodPost, "/webapi/v0/drafts/"+committedDraftID+"/send", "")
	if status != http.StatusConflict || result["error"].(map[string]any)["code"] != "draft_send_result_unknown" || committedUnknown.calls.Load() != 1 {
		t.Fatalf("repeated committed unknown Draft send = %d %#v calls=%d", status, result, committedUnknown.calls.Load())
	}

	var committedSent, committedQueueRows, committedDeliveryRows, committedClaims int
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id
		 WHERE m.account_id=$1 AND NOT m.expunged AND mb.su_sent
		   AND EXISTS (
		     SELECT 1 FROM outbound_deliveries delivery
		     WHERE delivery.account_id=m.account_id AND delivery.message_id=m.id
		       AND delivery.recipient='committed@example.net'
		   )`, accountID).Scan(&committedSent); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM queue WHERE account_id=$1 AND rcpt_to='committed@example.net'`, accountID).Scan(&committedQueueRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM outbound_deliveries WHERE account_id=$1 AND recipient='committed@example.net' AND status='queued'`, accountID).Scan(&committedDeliveryRows); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM draft_send_claims WHERE account_id=$1 AND status='processing'`, accountID).Scan(&committedClaims); err != nil {
		t.Fatal(err)
	}
	if committedSent != 1 || committedQueueRows != 1 || committedDeliveryRows != 1 || committedClaims != 2 {
		t.Fatalf("committed unknown evidence sent=%d queue=%d deliveries=%d claims=%d, want 1/1/1/2", committedSent, committedQueueRows, committedDeliveryRows, committedClaims)
	}
}
