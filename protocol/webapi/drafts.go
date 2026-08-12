package webapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
)

// GET /webapi/v0/drafts
func (s *Server) listDrafts(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	var out []messageSummary
	err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		mb, e := a.acc.MailboxFind(tx, "Drafts")
		if e != nil {
			return e
		}
		if mb == nil {
			return nil // no Drafts mailbox yet → empty list
		}
		msgs, e := tx.QueryMessage().FilterMailbox(mb.ID).SortUID().List()
		if e != nil {
			return e
		}
		mbNames := mailboxNames(tx, a.acc)
		for _, m := range msgs {
			out = append(out, summarize(ctx, a.acc, m, mbNames))
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if out == nil {
		out = []messageSummary{}
	}
	messageIDs := make([]int64, 0, len(out))
	for _, message := range out {
		if id, ok := parseEmailID(message.ID); ok {
			messageIDs = append(messageIDs, id)
		}
	}
	if policies, ok := a.acc.(store.OutboundPolicyDraftStore); ok {
		items, err := policies.OutboundPolicyDraftsForMessages(ctx, messageIDs)
		if err != nil {
			return 0, nil, err
		}
		for i := range out {
			id, ok := parseEmailID(out[i].ID)
			if !ok {
				continue
			}
			if draft, exists := items[id]; exists {
				policy := outboundPolicyProjection(draft, out[i].Subject)
				out[i].Policy = &policy
			}
		}
	}
	if drafts, ok := a.acc.(store.AgentOutboundDraftStore); ok {
		items, err := drafts.AgentOutboundDraftsForMessages(ctx, messageIDs)
		if err != nil {
			return 0, nil, err
		}
		for i := range out {
			id, ok := parseEmailID(out[i].ID)
			if !ok {
				continue
			}
			if draft, exists := items[id]; exists {
				projection := agentDraftProjection(draft, out[i].Subject, out[i].From, numericThreadID(out[i].ThreadID))
				out[i].AgentDraft = &projection
			}
		}
	}
	return http.StatusOK, map[string]any{"drafts": out}, nil
}

// POST /webapi/v0/drafts — compose and store a draft (no send).
func (s *Server) createDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if a.agentCredentialID > 0 {
		return 0, nil, errStatus(http.StatusForbidden, "owner_required", "an Agent must use the Agent Draft workflow")
	}
	var req sendRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, DraftBcc: req.Bcc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	m := &store.Message{}
	m.Flags.Draft = true
	if _, err := a.acc.DeliverMailbox(ctx, "Drafts", m, memBlob(raw)); err != nil {
		return 0, nil, internalErr("draft_failed", err)
	}
	return http.StatusCreated, map[string]any{"id": emailID(*m)}, nil
}

type updateDraftRequest struct {
	sendRequest
	DraftVersion *int `json:"draftVersion,omitempty"`
}

// PATCH /webapi/v0/drafts/{id} replaces an immutable Draft message with a new
// append-only version. Policy metadata follows the new Email id atomically.
func (s *Server) updateDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	existingRaw, err := readMessageBytes(ctx, a.acc, r.PathValue("id"))
	if err != nil {
		return 0, nil, err
	}
	existingEnvelope := parseEnvelope(existingRaw, nil, "")
	inReplyTo := ""
	if len(existingEnvelope.references) > 0 {
		inReplyTo = existingEnvelope.references[len(existingEnvelope.references)-1]
	}
	var req updateDraftRequest
	if err := decode(r, &req); err != nil {
		return 0, nil, err
	}
	raw, _, err := compose(composeInput{
		From: a.login, To: req.To, Cc: req.Cc, DraftBcc: req.Bcc, Subject: req.Subject,
		Text: req.Text, HTML: req.HTML, Attachments: req.Attachments,
		InReplyTo: inReplyTo, References: existingEnvelope.references,
	}, a.senderDomain())
	if err != nil {
		return 0, nil, err
	}
	digest := sha256.Sum256(raw)
	var (
		replacement   store.Message
		policy        store.OutboundPolicyDraft
		hasPolicy     bool
		agentDraft    store.AgentOutboundDraft
		hasAgentDraft bool
	)
	err = a.acc.Tx(ctx, func(tx store.Tx) error {
		current, mailbox, err := loadDraftMessage(tx, a.acc, r.PathValue("id"))
		if err != nil {
			return err
		}
		claimTx, ok := tx.(store.DraftSendClaimTx)
		if !ok {
			return errStatus(http.StatusNotImplemented, "draft_send_claim_unavailable", "durable Draft sending is unavailable")
		}
		if _, found, err := claimTx.FindDraftSendClaim(current.EffectiveEmailID()); err != nil {
			return err
		} else if found {
			return errStatus(http.StatusConflict, "draft_send_result_unknown", "this Draft was already submitted or has an unknown submission result; it cannot be edited")
		}
		policyTx, policyCapable := tx.(store.OutboundPolicyDraftTx)
		if policyCapable {
			policy, hasPolicy, err = policyTx.FindOutboundPolicyDraftByEmailID(current.EffectiveEmailID())
			if err != nil {
				return err
			}
		}
		agentDraftTx, agentDraftCapable := tx.(store.AgentOutboundDraftTx)
		if agentDraftCapable {
			agentDraft, hasAgentDraft, err = agentDraftTx.FindAgentOutboundDraftByEmailID(current.EffectiveEmailID())
			if err != nil {
				return err
			}
		}
		if hasPolicy && hasAgentDraft {
			return internalErr("draft_metadata_conflict", fmt.Errorf("draft has both policy and Agent workflow metadata"))
		}
		if hasPolicy {
			if a.agentCredentialID > 0 {
				return errStatus(http.StatusForbidden, "owner_required", "a policy draft must be edited by its human owner")
			}
			if req.DraftVersion == nil || *req.DraftVersion != policy.DraftVersion {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
		}
		if hasAgentDraft {
			if a.agentCredentialID > 0 {
				return errStatus(http.StatusForbidden, "owner_required", "an Agent-prepared draft must be edited by its human owner")
			}
			if req.DraftVersion == nil || *req.DraftVersion != agentDraft.DraftVersion {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
		}
		if a.agentCredentialID > 0 && !hasPolicy && !hasAgentDraft {
			return errStatus(http.StatusForbidden, "owner_required", "an unmarked draft must be edited by its human owner")
		}

		replacement.Flags.Draft = true
		if _, err := a.acc.MessageAdd(tx, mailbox, &replacement, memBlob(raw), store.AddOpts{}); err != nil {
			return err
		}
		if _, _, err := a.acc.MessageRemove(tx, 0, mailbox, store.RemoveOpts{Expunge: true}, current); err != nil {
			return err
		}
		if hasPolicy {
			updated, replaced, err := policyTx.ReplaceOutboundPolicyDraft(
				current.EffectiveEmailID(), policy.DraftVersion,
				replacement.EffectiveEmailID(), digest[:],
			)
			if err != nil {
				return err
			}
			if !replaced {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
			policy = updated
		}
		if hasAgentDraft {
			updated, replaced, err := agentDraftTx.ReplaceAgentOutboundDraft(
				current.EffectiveEmailID(), agentDraft.DraftVersion,
				replacement.EffectiveEmailID(), digest[:],
			)
			if err != nil {
				return err
			}
			if !replaced {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
			agentDraft = updated
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	version := 1
	if hasPolicy {
		version = policy.DraftVersion
	} else if hasAgentDraft {
		version = agentDraft.DraftVersion
	}
	return http.StatusOK, map[string]any{
		"id": emailID(replacement), "draftVersion": version,
	}, nil
}

type sendDraftRequest struct {
	DraftVersion *int `json:"draftVersion,omitempty"`
}

// POST /webapi/v0/drafts/{id}/send — submit an existing draft.
func (s *Server) sendDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if s.Submission == nil {
		return 0, nil, errStatus(http.StatusServiceUnavailable, "unavailable", "submission not enabled")
	}
	claimStore, ok := a.acc.(store.DraftSendClaimStore)
	if !ok {
		return 0, nil, errStatus(http.StatusNotImplemented, "draft_send_claim_unavailable", "durable Draft sending is unavailable")
	}
	var req sendDraftRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			return 0, nil, err
		}
	}
	id := r.PathValue("id")
	var (
		raw           []byte
		rcpts         []string
		policy        store.OutboundPolicyDraft
		hasPolicy     bool
		agentDraft    store.AgentOutboundDraft
		hasAgentDraft bool
		draftEmailID  int64
		draftVersion  int
		claim         store.DraftSendClaim
		claimed       bool
		mailFr        = a.login
	)
	err := a.acc.Tx(ctx, func(tx store.Tx) error {
		message, _, e := loadDraftMessage(tx, a.acc, id)
		if e != nil {
			return e
		}
		draftEmailID = message.EffectiveEmailID()
		if policyTx, ok := tx.(store.OutboundPolicyDraftTx); ok {
			policy, hasPolicy, e = policyTx.FindOutboundPolicyDraftByEmailID(message.EffectiveEmailID())
			if e != nil {
				return e
			}
		}
		if agentDraftTx, ok := tx.(store.AgentOutboundDraftTx); ok {
			agentDraft, hasAgentDraft, e = agentDraftTx.FindAgentOutboundDraftByEmailID(message.EffectiveEmailID())
			if e != nil {
				return e
			}
		}
		if hasPolicy && hasAgentDraft {
			return internalErr("draft_metadata_conflict", fmt.Errorf("draft has both policy and Agent workflow metadata"))
		}
		if hasPolicy {
			if a.agentCredentialID > 0 {
				return errStatus(http.StatusForbidden, "owner_required", "a policy draft must be sent by its human owner")
			}
			if req.DraftVersion == nil || *req.DraftVersion != policy.DraftVersion {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
			draftVersion = policy.DraftVersion
		}
		if hasAgentDraft {
			if a.agentCredentialID > 0 && !a.ownerConfirmedDraft {
				return errStatus(http.StatusForbidden, "owner_required", "an Agent-prepared Draft must be sent by its human owner")
			}
			if req.DraftVersion == nil || *req.DraftVersion != agentDraft.DraftVersion {
				return errStatus(http.StatusConflict, "draft_version_conflict", "the draft changed; reload the current version")
			}
			draftVersion = agentDraft.DraftVersion
		}
		if a.agentCredentialID > 0 && !hasAgentDraft {
			return errStatus(http.StatusForbidden, "owner_required", "an Agent credential cannot send Drafts directly; the human owner gateway must complete delivery")
		}
		br := a.acc.MessageReader(ctx, message)
		raw, e = io.ReadAll(br)
		closeErr := br.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		env := parseEnvelope(raw, nil, "")
		rcpts = allRecipients(env.to, env.cc, env.bcc)
		if len(rcpts) == 0 {
			return errStatus(http.StatusUnprocessableEntity, "no_recipients", "draft has no recipients")
		}
		claimTx, ok := tx.(store.DraftSendClaimTx)
		if !ok {
			return errStatus(http.StatusNotImplemented, "draft_send_claim_unavailable", "durable Draft sending is unavailable")
		}
		digest := sha256.Sum256(raw)
		claim, claimed, e = claimTx.ClaimDraftSend(draftEmailID, draftVersion, digest[:])
		if e != nil {
			return e
		}
		if !claimed && (claim.DraftVersion != draftVersion || !bytes.Equal(claim.ContentDigest, digest[:])) {
			return errStatus(http.StatusConflict, "draft_send_conflict", "the Draft send claim does not match the current version")
		}
		raw = stripRFCHeader(raw, "Bcc")
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	if !claimed {
		if claim.Status == "accepted" && claim.MessageID > 0 {
			return http.StatusAccepted, map[string]any{
				"outcome": "accepted", "submissionIds": claim.SubmissionIDs,
				"messageId": "E" + fmt.Sprint(claim.MessageID), "senderAddress": a.login,
			}, nil
		}
		return 0, nil, errStatus(http.StatusConflict, "draft_send_result_unknown", "this Draft is already being sent; do not retry automatically")
	}
	abandonClaim := func() {
		cleanupCtx, cancel := cleanupContext(ctx)
		defer cancel()
		if err := claimStore.AbandonDraftSendClaim(cleanupCtx, draftEmailID); err != nil && s.Log != nil {
			s.Log.WarnContext(cleanupCtx, "Draft send claim cleanup failed", "draft_id", id, "err", err)
		}
	}
	sent, err := saveSentCopy(ctx, a.acc, raw)
	if err != nil {
		abandonClaim()
		return 0, nil, internalErr("sent_copy_failed", err)
	}
	ids, err := s.Submission.SubmitForMessage(ctx, a.scope.Tenant().ID, a.acc.ID(), sent.EffectiveEmailID(), mailFr, rcpts, raw)
	if err != nil {
		if submit.IsResultUnknown(err) {
			return 0, nil, resultUnknownStatusError(
				"draft_send_result_unknown",
				"the Draft submission result is unknown; inspect Sent and do not retry automatically",
				err,
			)
		}
		s.cleanupFailedSubmissionSentCopy(ctx, a.acc, sent.EffectiveEmailID())
		abandonClaim()
		return 0, nil, internalErr("submit_failed", err)
	}
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	if err := claimStore.CompleteDraftSendClaim(cleanupCtx, draftEmailID, sent.EffectiveEmailID(), ids); err != nil && s.Log != nil {
		s.Log.WarnContext(cleanupCtx, "accepted Draft send claim completion failed", "draft_id", id, "err", err)
	}
	// Submission is already accepted. Cleanup failure must not produce a
	// retryable error that could make the owner send the same message again.
	if err := removeDraft(cleanupCtx, a.acc, id); err != nil && s.Log != nil {
		s.Log.WarnContext(cleanupCtx, "accepted draft cleanup failed", "draft_id", id, "err", err)
	} else if err == nil {
		if err := claimStore.DeleteDraftSendClaim(cleanupCtx, draftEmailID); err != nil && s.Log != nil {
			s.Log.WarnContext(cleanupCtx, "accepted Draft send claim deletion failed", "draft_id", id, "err", err)
		}
	}
	return http.StatusAccepted, map[string]any{
		"outcome": "accepted", "submissionIds": ids, "messageId": emailID(sent),
		"senderAddress": a.login,
	}, nil
}

// DELETE /webapi/v0/drafts/{id}
func (s *Server) deleteDraft(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	if err := removeDraftAuthorized(ctx, a, r.PathValue("id")); err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

func removeDraftAuthorized(ctx context.Context, a authCtx, id string) error {
	return removeDraftWithCheck(ctx, a.acc, id, func(tx store.Tx, message store.Message) error {
		claimTx, ok := tx.(store.DraftSendClaimTx)
		if !ok {
			return errStatus(http.StatusNotImplemented, "draft_send_claim_unavailable", "durable Draft sending is unavailable")
		}
		if claim, found, err := claimTx.FindDraftSendClaim(message.EffectiveEmailID()); err != nil {
			return err
		} else if found && claim.Status == "processing" {
			return errStatus(http.StatusConflict, "draft_send_result_unknown", "this Draft has an unknown submission result and cannot be deleted")
		}
		hasPolicy := false
		if policyTx, ok := tx.(store.OutboundPolicyDraftTx); ok {
			_, found, err := policyTx.FindOutboundPolicyDraftByEmailID(message.EffectiveEmailID())
			if err != nil {
				return err
			}
			hasPolicy = found
		}
		hasAgentDraft := false
		if agentDraftTx, ok := tx.(store.AgentOutboundDraftTx); ok {
			_, found, err := agentDraftTx.FindAgentOutboundDraftByEmailID(message.EffectiveEmailID())
			if err != nil {
				return err
			}
			hasAgentDraft = found
		}
		if hasPolicy && hasAgentDraft {
			return internalErr("draft_metadata_conflict", fmt.Errorf("draft has both policy and Agent workflow metadata"))
		}
		if a.agentCredentialID > 0 && !hasAgentDraft {
			return errStatus(http.StatusForbidden, "owner_required", "an Agent may delete only a server-prepared Agent Draft")
		}
		return nil
	})
}

func loadDraftMessage(tx store.Tx, acc store.Account, id string) (store.Message, *store.Mailbox, error) {
	msgs, err := loadGroup(tx, acc, id)
	if err != nil {
		return store.Message{}, nil, err
	}
	for _, message := range msgs {
		mailbox, err := mailboxByID(tx, acc, message.MailboxID)
		if err != nil {
			return store.Message{}, nil, err
		}
		if mailbox.Draft || strings.EqualFold(mailbox.Name, "Drafts") {
			return message, mailbox, nil
		}
	}
	return store.Message{}, nil, errStatus(http.StatusNotFound, "not_found", "no such draft")
}

func removeDraft(ctx context.Context, acc store.Account, id string) error {
	return removeDraftWithCheck(ctx, acc, id, nil)
}

func removeDraftWithCheck(ctx context.Context, acc store.Account, id string, check func(store.Tx, store.Message) error) error {
	return acc.Tx(ctx, func(tx store.Tx) error {
		message, mailbox, err := loadDraftMessage(tx, acc, id)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(tx, message); err != nil {
				return err
			}
		}
		if policyTx, ok := tx.(store.OutboundPolicyDraftTx); ok {
			if err := policyTx.DeleteOutboundPolicyDraft(message.EffectiveEmailID()); err != nil {
				return err
			}
		}
		if agentDraftTx, ok := tx.(store.AgentOutboundDraftTx); ok {
			if err := agentDraftTx.DeleteAgentOutboundDraft(message.EffectiveEmailID()); err != nil {
				return err
			}
		}
		_, _, err = acc.MessageRemove(tx, 0, mailbox, store.RemoveOpts{Expunge: true}, message)
		return err
	})
}

// stripRFCHeader removes one header and its folded continuation lines while
// leaving the MIME body byte-for-byte unchanged. Draft-only Bcc recipients must
// never appear in the Sent copy or SMTP DATA.
func stripRFCHeader(raw []byte, name string) []byte {
	separator := []byte("\r\n")
	boundary := []byte("\r\n\r\n")
	end := bytes.Index(raw, boundary)
	if end < 0 {
		separator = []byte("\n")
		boundary = []byte("\n\n")
		end = bytes.Index(raw, boundary)
	}
	if end < 0 {
		return raw
	}
	lines := bytes.Split(raw[:end], separator)
	kept := make([][]byte, 0, len(lines))
	skipping := false
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if skipping {
				continue
			}
			kept = append(kept, line)
			continue
		}
		skipping = false
		colon := bytes.IndexByte(line, ':')
		if colon >= 0 && strings.EqualFold(string(line[:colon]), name) {
			skipping = true
			continue
		}
		kept = append(kept, line)
	}
	out := bytes.Join(kept, separator)
	out = append(out, boundary...)
	out = append(out, raw[end+len(boundary):]...)
	return out
}
