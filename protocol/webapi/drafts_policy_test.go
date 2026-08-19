package webapi

import (
	"encoding/base64"
	"reflect"
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

	intent, err := agentDraftPolicyIntent(raw, store.AgentOutboundDraft{
		DraftType: agentDraftTypeReply, SourceEmailID: 42,
	})
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
}
