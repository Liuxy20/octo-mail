package webapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
)

const agentAutomationHeader = "X-Octo-Automation"
const (
	agentAutomationAutoReply           = "auto-reply"
	agentAutomationOwnerConfirmedDraft = "owner-confirmed-draft"
)

// hAgentConfirmed keeps non-automated Agent writes behind the human-owner
// gateway. Scoped automatic replies retain their separate server-authorized
// path; owner and gateway principals keep their existing behavior.
func (s *Server) hAgentConfirmed(operation string, fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.auth(r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if a.agentCredentialID > 0 {
			var authorizationErr error
			automation := strings.TrimSpace(r.Header.Get(agentAutomationHeader))
			if automation != "" {
				authorizationErr = s.requireScopedAutomation(w, r, a, operation)
				if authorizationErr == nil && automation == agentAutomationOwnerConfirmedDraft {
					a.ownerConfirmedDraft = true
				}
			} else {
				authorizationErr = errStatus(http.StatusForbidden, "owner_required", "this Agent Mail action must be completed by the human owner gateway")
			}
			if authorizationErr != nil {
				s.writeErr(w, r, authorizationErr)
				return
			}
		}
		status, body, err := fn(r.Context(), a, r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if status == http.StatusNoContent || body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	}
}

func (s *Server) requireScopedAutomation(w http.ResponseWriter, r *http.Request, a authCtx, operation string) error {
	automation := strings.TrimSpace(r.Header.Get(agentAutomationHeader))
	if !validOutboundIdempotencyKey(strings.TrimSpace(r.Header.Get(outboundIdempotencyHeader))) {
		return errStatus(http.StatusBadRequest, "idempotency_key_required", "automatic replies require a valid idempotency key")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxMessageSize()))
	if err != nil {
		return errStatus(http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := validateAutomatedWrite(automation, operation, r, body); err != nil {
		return err
	}
	dir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
	if !ok {
		return errStatus(http.StatusNotImplemented, "agent_automation_unavailable", "Agent Mail automation is not available")
	}
	allowed, err := dir.AgentAutomationAllowed(r.Context(), a.agentCredentialID, operation)
	if err != nil {
		return err
	}
	if !allowed {
		return errStatus(http.StatusForbidden, "automation_not_authorized", "automatic sending is not enabled for this mailbox binding")
	}
	return nil
}

func validateAutomatedWrite(automation, operation string, r *http.Request, body []byte) error {
	if r.Method != http.MethodPost {
		return errStatus(http.StatusForbidden, "automation_not_authorized", "this Agent Mail operation is outside the approved automation scope")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return errStatus(http.StatusForbidden, "automation_not_authorized", "automatic sending requires a valid JSON body")
	}
	switch automation {
	case agentAutomationAutoReply:
		if operation != "mail.message.reply" || !strings.HasSuffix(r.URL.Path, "/reply") || len(payload) != 1 {
			return errStatus(http.StatusForbidden, "automation_not_authorized", "automatic replies must contain only a plain-text body")
		}
		if !validAutomatedText(payload["text"]) {
			return errStatus(http.StatusForbidden, "automation_not_authorized", "automatic replies require a bounded plain-text body")
		}
	case agentAutomationOwnerConfirmedDraft:
		if operation != "mail.draft.send" ||
			!strings.HasPrefix(r.URL.Path, "/webapi/v0/drafts/") ||
			!strings.HasSuffix(r.URL.Path, "/send") || len(payload) != 1 {
			return errStatus(http.StatusForbidden, "automation_not_authorized", "owner-confirmed delivery is limited to one versioned Agent Draft")
		}
		var draftVersion int
		if raw, ok := payload["draftVersion"]; !ok || json.Unmarshal(raw, &draftVersion) != nil || draftVersion <= 0 {
			return errStatus(http.StatusForbidden, "automation_not_authorized", "owner-confirmed delivery requires one positive Draft version")
		}
	default:
		return errStatus(http.StatusForbidden, "automation_not_authorized", "unknown Agent Mail automation mode")
	}
	return nil
}

func validAutomatedText(raw json.RawMessage) bool {
	var text string
	return json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != "" && len(text) <= 100000
}
