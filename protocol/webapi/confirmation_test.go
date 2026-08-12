package webapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

type scopedAutomationDirectory struct {
	directory.Directory
	directory.AgentAuthorizationDirectory
	allowed bool
}

func (d scopedAutomationDirectory) AgentAutomationAllowed(_ context.Context, _ int64, operation string) (bool, error) {
	return d.allowed, nil
}

func TestRequireScopedAutomation(t *testing.T) {
	tests := []struct {
		name       string
		allowed    bool
		operation  string
		method     string
		path       string
		body       string
		automation string
		wantCode   string
	}{
		{
			name:    "allows a bounded plain-text reply when the binding opted in",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"Thanks"}`,
			automation: agentAutomationAutoReply,
		},
		{
			name:    "allows one exact owner-confirmed versioned Draft send",
			allowed: true, operation: "mail.draft.send", method: http.MethodPost,
			path: "/webapi/v0/drafts/E9/send", body: `{"draftVersion":2}`,
			automation: agentAutomationOwnerConfirmedDraft,
		},
		{
			name:    "rejects extra fields from an owner-confirmed Draft send",
			allowed: true, operation: "mail.draft.send", method: http.MethodPost,
			path: "/webapi/v0/drafts/E9/send", body: `{"draftVersion":2,"to":["other@example.net"]}`,
			automation: agentAutomationOwnerConfirmedDraft,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "rejects a missing Draft version",
			allowed: true, operation: "mail.draft.send", method: http.MethodPost,
			path: "/webapi/v0/drafts/E9/send", body: `{}`,
			automation: agentAutomationOwnerConfirmedDraft,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "rejects the owner-confirmed marker on another operation",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E9/reply", body: `{"draftVersion":2}`,
			automation: agentAutomationOwnerConfirmedDraft,
			wantCode:   "automation_not_authorized",
		},
		{
			name:      "denies a reply when the binding did not opt in",
			operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"Thanks"}`,
			automation: agentAutomationAutoReply,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "denies direct automatic send outside the idempotent intent endpoint",
			allowed: true, operation: "mail.message.send", method: http.MethodPost,
			path: "/webapi/v0/messages", body: `{"to":["person@example.net"],"subject":"Hello","text":"Hi"}`,
			automation: "automatic-send",
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "denies reply all",
			allowed: true, operation: "mail.message.reply_all", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply-all", body: `{"text":"Thanks"}`,
			automation: agentAutomationAutoReply,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "denies HTML",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"Thanks","html":"<b>Thanks</b>"}`,
			automation: agentAutomationAutoReply,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "denies attachments",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"Thanks","attachments":[]}`,
			automation: agentAutomationAutoReply,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "denies an empty body",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"  "}`,
			automation: agentAutomationAutoReply,
			wantCode:   "automation_not_authorized",
		},
		{
			name:    "requires an idempotency key",
			allowed: true, operation: "mail.message.reply", method: http.MethodPost,
			path: "/webapi/v0/messages/E1/reply", body: `{"text":"Thanks"}`,
			automation: agentAutomationAutoReply,
			wantCode:   "idempotency_key_required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Dir: scopedAutomationDirectory{allowed: tt.allowed}}
			r, err := http.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set(agentAutomationHeader, tt.automation)
			if tt.name != "requires an idempotency key" {
				r.Header.Set(outboundIdempotencyHeader, "automatic-reply-test-key")
			}
			err = s.requireScopedAutomation(nil, r, authCtx{agentCredentialID: 7}, tt.operation)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("requireScopedAutomation() error = %v", err)
				}
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil || string(body) != tt.body {
					t.Fatalf("request body was not restored: %q, err=%v", body, readErr)
				}
				return
			}
			status, ok := err.(*statusError)
			wantStatus := http.StatusForbidden
			if tt.wantCode == "idempotency_key_required" {
				wantStatus = http.StatusBadRequest
			}
			if !ok || status.code != tt.wantCode || status.status != wantStatus {
				t.Fatalf("error = %#v, want %d %s", err, wantStatus, tt.wantCode)
			}
		})
	}
}
