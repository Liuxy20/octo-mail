package webapi

import (
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
)

func TestAgentDraftPolicyIntentIncludesCompleteDraft(t *testing.T) {
	raw, _, err := compose(composeInput{
		From: "agent@example.com", To: []string{"to@example.net"},
		Cc: []string{"cc@example.net"}, DraftBcc: []string{"bcc@example.net"},
		Subject: "Policy subject", Text: "plain body", HTML: "<p>HTML body</p>",
		Attachments: []attachment{{
			Filename: "note.txt", ContentType: "text/plain",
			Content: base64.StdEncoding.EncodeToString([]byte("attachment text must not become the body")),
		}},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	replyDraft := &store.AgentOutboundDraft{
		DraftType: agentDraftTypeReply, SourceEmailID: 42,
	}
	intent, err := agentDraftPolicyIntent(raw, replyDraft)
	if err != nil {
		t.Fatal(err)
	}
	want := outboundpolicy.Intent{
		Source: outboundpolicy.SourceInboundAutoReply, Operation: "mail.message.reply", SourceEmailID: "E42",
		To: []string{"to@example.net"}, Cc: []string{"cc@example.net"}, Bcc: []string{"bcc@example.net"},
		Subject: "Policy subject", Text: "plain body", HTML: "<p>HTML body</p>", AttachmentCount: 1,
	}
	if !reflect.DeepEqual(intent, want) {
		t.Fatalf("policy intent = %#v, want %#v", intent, want)
	}

	humanDraftIntent, err := agentDraftPolicyIntent(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	want.Source = outboundpolicy.SourceOwnerDirect
	want.Operation = "mail.message.send"
	want.SourceEmailID = ""
	if !reflect.DeepEqual(humanDraftIntent, want) {
		t.Fatalf("human Draft policy intent = %#v, want %#v", humanDraftIntent, want)
	}
}

func TestAgentDraftPolicyIntentIncludesEveryTextLeaf(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: agent@example.com",
		"To: to@example.net",
		"Subject: Multi-leaf policy",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="outer"`,
		"",
		"--outer",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"harmless first plain leaf",
		"--outer",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"review-only-second-plain-leaf",
		"--outer",
		`Content-Type: multipart/alternative; boundary="alternative"`,
		"",
		"--alternative",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>harmless first HTML leaf</p>",
		"--alternative",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>review-only-second-html-leaf</p>",
		"--alternative--",
		"--outer--",
		"",
	}, "\r\n"))

	intent, err := agentDraftPolicyIntent(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]string{
		"text": intent.Text,
		"html": intent.HTML,
	} {
		if !strings.Contains(value, "first") || !strings.Contains(value, "review-only-second-") {
			t.Fatalf("%s policy content = %q, want every same-subtype leaf", field, value)
		}
	}
	for _, term := range []string{"review-only-second-plain-leaf", "review-only-second-html-leaf"} {
		decision, err := outboundpolicy.NewKeywordEvaluator([]string{term}).Evaluate(context.Background(), intent)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Outcome != outboundpolicy.OutcomeOwnerReviewRequired {
			t.Fatalf("policy outcome for %q = %q, want %q", term, decision.Outcome, outboundpolicy.OutcomeOwnerReviewRequired)
		}
	}
}
