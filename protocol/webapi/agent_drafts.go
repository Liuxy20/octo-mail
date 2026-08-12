package webapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/mjl-/mox/smtp"
)

const (
	agentDraftTypePendingConfirmation = "agent_pending_confirmation"
	agentDraftTypeReply               = "agent_reply_draft"
)

type agentDraftInfo struct {
	Outcome       string `json:"outcome"`
	Status        string `json:"status"`
	DraftType     string `json:"draftType"`
	DraftID       string `json:"draftId"`
	DraftVersion  int    `json:"draftVersion"`
	DraftSubject  string `json:"draftSubject"`
	SenderAddress string `json:"senderAddress,omitempty"`
	SourceEmailID string `json:"sourceEmailId,omitempty"`
	ThreadID      string `json:"threadId,omitempty"`
}

// POST /webapi/v0/agent-send-intents is the single authoritative decision
// point for a proactive Agent write. The caller submits one immutable intent;
// octo-mail evaluates policy and the binding's current outbound mode, then
// either submits the message or persists the appropriate Draft. The Plugin
// must not read the mode and race a second request against a mode change.
func (s *Server) createAgentSendIntent(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := requireAgentDraftCredential(a); err != nil {
		return 0, nil, err
	}
	requestKey := strings.TrimSpace(r.Header.Get(outboundIdempotencyHeader))
	if !validOutboundIdempotencyKey(requestKey) {
		return 0, nil, errStatus(http.StatusBadRequest, "idempotency_key_required", "Agent send intent requires a valid idempotency key")
	}
	var req sendRequest
	if err := decodeStrict(r, &req); err != nil {
		return 0, nil, err
	}
	if err := validateAgentSendIntent(req); err != nil {
		return 0, nil, err
	}

	// The outbound bytes never expose Bcc. A held Draft is composed separately
	// below so its owner can still review the original Bcc recipients.
	outboundRaw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	draftRaw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, DraftBcc: req.Bcc,
		Subject: req.Subject, Text: req.Text, HTML: req.HTML,
		Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	if err := s.enforceAgentOutboundPolicy(ctx, a, r, outboundpolicy.Intent{
		Source: outboundpolicy.SourceOwnerDirect, Operation: "mail.message.send",
		To: req.To, Cc: req.Cc, Bcc: req.Bcc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, AttachmentCount: len(req.Attachments),
	}, draftRaw); err != nil {
		return 0, nil, err
	}

	dir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
	if !ok {
		return 0, nil, errStatus(http.StatusNotImplemented, "agent_automation_unavailable", "Agent Mail automation is not available")
	}
	automatic, err := dir.AgentAutomationAllowed(ctx, a.agentCredentialID, "mail.message.send")
	if err != nil {
		return 0, nil, err
	}
	// Automatic send is deliberately narrow. HTML or attachments are retained
	// for owner confirmation rather than being silently dropped or auto-sent.
	if automatic && eligibleAutomaticSend(req) {
		return s.submitAgentSendIntent(ctx, a, requestKey, req, outboundRaw)
	}

	draft, message, err := saveAgentOutboundDraft(ctx, a.acc, r, draftRaw, store.AgentOutboundDraft{
		DraftType:     agentDraftTypePendingConfirmation,
		Status:        "pending_confirmation",
		ContentDigest: agentDraftIntentDigest(agentDraftTypePendingConfirmation, "", req),
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, agentDraftProjection(draft, req.Subject, a.login, message.ThreadID), nil
}

func (s *Server) submitAgentSendIntent(ctx context.Context, a authCtx, requestKey string, req sendRequest, raw []byte) (int, any, error) {
	digest := agentDraftIntentDigest("agent_automatic_send", "", req)
	intent, claimed, err := s.claimAgentSendIntent(ctx, a, requestKey, digest)
	if err != nil {
		return 0, nil, err
	}
	if !claimed {
		return existingAgentSendIntentResult(a, intent)
	}

	sent, submissionIDs, err := s.enqueueComposedMessage(ctx, a, req.To, req.Cc, req.Bcc, raw)
	if err != nil {
		if submit.IsResultUnknown(err) {
			return 0, nil, resultUnknownStatusError(
				"send_intent_result_unknown",
				"this send intent may have been accepted; inspect Sent and do not retry automatically",
				err,
			)
		}
		s.abandonAgentSendIntent(ctx, a, requestKey)
		return 0, nil, err
	}
	s.completeAgentSendIntent(ctx, a, requestKey, sent.EffectiveEmailID(), submissionIDs)
	return http.StatusAccepted, map[string]any{
		"outcome": "accepted", "messageId": emailID(sent), "submissionIds": submissionIDs,
		"senderAddress": a.login,
	}, nil
}

func (s *Server) claimAgentSendIntent(ctx context.Context, a authCtx, requestKey string, digest []byte) (store.AgentSendIntent, bool, error) {
	intents, ok := a.acc.(store.AgentSendIntentStore)
	if !ok {
		return store.AgentSendIntent{}, false, errStatus(http.StatusNotImplemented, "send_intent_unavailable", "automatic Agent send idempotency is not available")
	}
	intent, claimed, err := intents.ClaimAgentSendIntent(ctx, requestKey, digest)
	if err != nil {
		return store.AgentSendIntent{}, false, internalErr("send_intent_claim_failed", err)
	}
	if !bytes.Equal(intent.ContentDigest, digest) {
		return store.AgentSendIntent{}, false, errStatus(http.StatusConflict, "idempotency_key_conflict", "idempotency key was already used for different send content")
	}
	return intent, claimed, nil
}

func existingAgentSendIntentResult(a authCtx, intent store.AgentSendIntent) (int, any, error) {
	if intent.Status == "accepted" && intent.MessageID > 0 {
		return http.StatusAccepted, map[string]any{
			"outcome": "accepted", "messageId": "E" + strconv.FormatInt(intent.MessageID, 10),
			"submissionIds": intent.SubmissionIDs, "senderAddress": a.login,
		}, nil
	}
	return 0, nil, errStatus(http.StatusConflict, "send_intent_result_unknown", "this send intent may already be processing; inspect Sent before retrying")
}

func (s *Server) abandonAgentSendIntent(ctx context.Context, a authCtx, requestKey string) {
	intents, ok := a.acc.(store.AgentSendIntentStore)
	if !ok {
		return
	}
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	if err := intents.AbandonAgentSendIntent(cleanupCtx, requestKey); err != nil && s.Log != nil {
		s.Log.WarnContext(cleanupCtx, "failed to abandon unsent Agent send intent", "err", err)
	}
}

func (s *Server) completeAgentSendIntent(ctx context.Context, a authCtx, requestKey string, messageID int64, submissionIDs []int64) {
	intents, ok := a.acc.(store.AgentSendIntentStore)
	if !ok {
		return
	}
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	if err := intents.CompleteAgentSendIntent(cleanupCtx, requestKey, messageID, submissionIDs); err != nil && s.Log != nil {
		// The queue side effect is already durable. Never turn bookkeeping failure
		// into a retryable response that could duplicate the email.
		s.Log.WarnContext(cleanupCtx, "accepted Agent send intent completion failed", "message_id", messageID, "err", err)
	}
}

func eligibleAutomaticSend(req sendRequest) bool {
	return strings.TrimSpace(req.Text) != "" && len(req.Text) <= 100000 && req.HTML == "" && len(req.Attachments) == 0
}

func validateAgentSendIntent(req sendRequest) error {
	if len(req.To) == 0 {
		return errStatus(http.StatusBadRequest, "invalid_body", "at least one recipient in 'to' is required")
	}
	recipients := allRecipients(req.To, req.Cc, req.Bcc)
	if len(recipients) > 100 {
		return errStatus(http.StatusBadRequest, "too_many_recipients", "Agent send intent supports at most 100 recipients")
	}
	for _, recipient := range recipients {
		if _, err := smtp.ParseAddress(recipient); err != nil {
			return errStatus(http.StatusBadRequest, "invalid_recipient", "Agent send intent contains an invalid recipient")
		}
	}
	if len(req.Subject) > 998 {
		return errStatus(http.StatusBadRequest, "subject_too_large", "Agent send intent subject exceeds 998 characters")
	}
	if len(req.Text) > 100000 {
		return errStatus(http.StatusRequestEntityTooLarge, "message_too_large", "Agent send intent plain-text body exceeds 100000 characters")
	}
	return nil
}

// POST /webapi/v0/agent-drafts prepares a proactive Agent message as a Draft.
// Draft creation has no external send side effect, so confirmation remains on
// the later send operation; outbound policy is still evaluated before the
// sendable Draft metadata is persisted.
func (s *Server) createAgentDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := requireAgentDraftCredential(a); err != nil {
		return 0, nil, err
	}
	var req sendRequest
	if err := decodeStrict(r, &req); err != nil {
		return 0, nil, err
	}
	if len(req.To) == 0 {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_body", "at least one recipient in 'to' is required")
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, DraftBcc: req.Bcc,
		Subject: req.Subject, Text: req.Text, HTML: req.HTML,
		Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	if err := s.enforceAgentOutboundPolicy(ctx, a, r, outboundpolicy.Intent{
		Source: outboundpolicy.SourceOwnerDirect, Operation: "mail.message.send",
		To: req.To, Cc: req.Cc, Bcc: req.Bcc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, AttachmentCount: len(req.Attachments),
	}, raw); err != nil {
		return 0, nil, err
	}
	draft, message, err := saveAgentOutboundDraft(ctx, a.acc, r, raw, store.AgentOutboundDraft{
		DraftType:     agentDraftTypePendingConfirmation,
		Status:        "pending_confirmation",
		ContentDigest: agentDraftIntentDigest(agentDraftTypePendingConfirmation, "", req),
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, agentDraftProjection(draft, req.Subject, a.login, message.ThreadID), nil
}

// POST /webapi/v0/messages/{id}/reply-draft prepares a reply in the original
// RFC thread without sending it.
func (s *Server) createAgentReplyDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := requireAgentDraftCredential(a); err != nil {
		return 0, nil, err
	}
	sourceID := r.PathValue("id")
	var req replyRequest
	if err := decodeStrict(r, &req); err != nil {
		return 0, nil, err
	}
	sourceRaw, err := readMessageBytes(ctx, a.acc, sourceID)
	if err != nil {
		return 0, nil, err
	}
	env := parseEnvelope(sourceRaw, nil)
	to, cc := replyRecipients(env, a.login, false)
	if len(to) == 0 {
		return 0, nil, errStatus(http.StatusUnprocessableEntity, "no_recipients", "original has no reply recipient")
	}
	subject := ensurePrefix(env.subject, "Re: ")
	raw, _, err := compose(composeInput{
		From: a.login, To: to, Cc: cc, Subject: subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
		InReplyTo: env.messageID, References: append(env.references, env.messageID),
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	if err := s.enforceAgentOutboundPolicy(ctx, a, r, outboundpolicy.Intent{
		Source: outboundpolicy.SourceInboundAutoReply, Operation: "mail.message.reply",
		SourceEmailID: sourceID, To: to, Cc: cc, Subject: subject,
		Text: req.Text, HTML: req.HTML, AttachmentCount: len(req.Attachments),
	}, raw); err != nil {
		return 0, nil, err
	}
	draft, message, err := saveAgentOutboundDraft(ctx, a.acc, r, raw, store.AgentOutboundDraft{
		DraftType:     agentDraftTypeReply,
		Status:        "pending_confirmation",
		SourceEmailID: numericEmailID(sourceID),
		ContentDigest: agentDraftIntentDigest(agentDraftTypeReply, sourceID, req),
	})
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, agentDraftProjection(draft, subject, a.login, message.ThreadID), nil
}

func requireAgentDraftCredential(a authCtx) error {
	if a.agentCredentialID <= 0 {
		return errStatus(http.StatusForbidden, "agent_credential_required", "this Draft preparation endpoint requires an Agent mailbox credential")
	}
	return nil
}

func saveAgentOutboundDraft(
	ctx context.Context,
	acc store.Account,
	r *http.Request,
	raw []byte,
	draft store.AgentOutboundDraft,
) (store.AgentOutboundDraft, store.Message, error) {
	requestKey := strings.TrimSpace(r.Header.Get(outboundIdempotencyHeader))
	if !validOutboundIdempotencyKey(requestKey) {
		return store.AgentOutboundDraft{}, store.Message{}, errStatus(http.StatusBadRequest, "idempotency_key_required", "Agent Draft preparation requires a valid idempotency key")
	}
	if len(draft.ContentDigest) == 0 {
		digest := sha256.Sum256(raw)
		draft.ContentDigest = append([]byte(nil), digest[:]...)
	}
	if len(draft.ContentDigest) != sha256.Size {
		return store.AgentOutboundDraft{}, store.Message{}, internalErr("invalid_agent_draft_digest", fmt.Errorf("Agent Draft digest must be %d bytes", sha256.Size))
	}
	draft.DraftVersion = 1
	draft.ContentDigest = append([]byte(nil), draft.ContentDigest...)
	draft.IdempotencyKey = scopedOutboundIdempotencyKey(acc.ID(), requestKey)
	var message store.Message
	err := acc.Tx(ctx, func(tx store.Tx) error {
		draftTx, ok := tx.(store.AgentOutboundDraftTx)
		if !ok {
			return fmt.Errorf("agent outbound draft transaction capability unavailable")
		}
		existing, found, err := draftTx.FindAgentOutboundDraftByIdempotencyKey(draft.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(existing.ContentDigest, draft.ContentDigest) {
				return errStatus(http.StatusConflict, "idempotency_key_conflict", "idempotency key was already used for different Draft content")
			}
			messages, err := loadGroup(tx, acc, "E"+strconv.FormatInt(existing.EmailID, 10))
			if err != nil {
				return err
			}
			draft = existing
			message = messages[0]
			return nil
		}

		mailbox, err := ensureDraftMailbox(tx, acc)
		if err != nil {
			return err
		}
		message.Flags.Draft = true
		if _, err := acc.MessageAdd(tx, mailbox, &message, memBlob(raw), store.AddOpts{}); err != nil {
			return err
		}
		draft.EmailID = message.EffectiveEmailID()
		return draftTx.PutAgentOutboundDraft(draft)
	})
	if err != nil {
		return store.AgentOutboundDraft{}, store.Message{}, err
	}
	return draft, message, nil
}

func agentDraftIntentDigest(draftType, sourceEmailID string, value any) []byte {
	payload, _ := json.Marshal(struct {
		DraftType     string `json:"draftType"`
		SourceEmailID string `json:"sourceEmailId,omitempty"`
		Value         any    `json:"value"`
	}{DraftType: draftType, SourceEmailID: sourceEmailID, Value: value})
	digest := sha256.Sum256(payload)
	return append([]byte(nil), digest[:]...)
}

func ensureDraftMailbox(tx store.Tx, acc store.Account) (*store.Mailbox, error) {
	mailboxes, err := tx.QueryMailbox().List()
	if err != nil {
		return nil, err
	}
	for i := range mailboxes {
		if mailboxes[i].Draft {
			return &mailboxes[i], nil
		}
	}
	mailbox, err := acc.MailboxFind(tx, "Drafts")
	if err != nil {
		return nil, err
	}
	if mailbox == nil {
		created, _, err := acc.MailboxEnsure(tx, "Drafts", true, store.SpecialUse{Draft: true}, nil)
		return &created, err
	}
	if !mailbox.Draft {
		specialUse := mailbox.SpecialUse
		specialUse.Draft = true
		if _, err := acc.MailboxSetSpecialUse(tx, mailbox, specialUse); err != nil {
			return nil, err
		}
	}
	return mailbox, nil
}

func validOutboundIdempotencyKey(key string) bool {
	return len(key) >= 8 && len(key) <= 200 && strings.IndexFunc(key, func(r rune) bool {
		return r < 0x21 || r > 0x7e
	}) < 0
}

func agentDraftProjection(draft store.AgentOutboundDraft, subject, senderAddress string, threadID int64) agentDraftInfo {
	info := agentDraftInfo{
		Outcome: "owner_confirmation_required", Status: draft.Status,
		DraftType: draft.DraftType, DraftID: "E" + strconv.FormatInt(draft.EmailID, 10),
		DraftVersion: draft.DraftVersion, DraftSubject: subject,
		SenderAddress: senderAddress,
	}
	if draft.SourceEmailID > 0 {
		info.SourceEmailID = "E" + strconv.FormatInt(draft.SourceEmailID, 10)
	}
	if threadID > 0 {
		info.ThreadID = "T" + strconv.FormatInt(threadID, 10)
	}
	return info
}
