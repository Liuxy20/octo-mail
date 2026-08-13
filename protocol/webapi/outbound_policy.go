package webapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
)

const outboundIdempotencyHeader = "X-Octo-Idempotency-Key"

func outboundPolicySource(r *http.Request) string {
	if strings.TrimSpace(r.Header.Get(agentAutomationHeader)) == agentAutomationAutoReply {
		return outboundpolicy.SourceInboundAutoReply
	}
	return outboundpolicy.SourceOwnerDirect
}

type outboundPolicyInfo struct {
	Outcome       string                       `json:"outcome"`
	Status        string                       `json:"status"`
	DraftVersion  int                          `json:"draftVersion"`
	PolicyVersion string                       `json:"policyVersion"`
	Reasons       []store.OutboundPolicyReason `json:"reasons"`
	Source        string                       `json:"source"`
	SourceEmailID string                       `json:"sourceEmailId,omitempty"`
	DraftID       string                       `json:"draftId"`
	DraftSubject  string                       `json:"draftSubject"`
}

func (s *Server) enforceAgentOutboundPolicy(
	ctx context.Context,
	a authCtx,
	r *http.Request,
	intent outboundpolicy.Intent,
	raw []byte,
) error {
	if a.agentCredentialID <= 0 || s.OutboundPolicy == nil {
		return nil
	}
	decision, err := s.OutboundPolicy.Evaluate(ctx, intent)
	if err != nil {
		return internalErr("outbound_policy_failed", err)
	}
	switch decision.Outcome {
	case outboundpolicy.OutcomeAllow:
		return nil
	case outboundpolicy.OutcomeOwnerReviewRequired:
		// A model/client value is not authorization. It is only a caller-generated
		// dedupe token and is salted with the authenticated account below.
		requestKey := strings.TrimSpace(r.Header.Get(outboundIdempotencyHeader))
		if !validOutboundIdempotencyKey(requestKey) {
			return errStatus(http.StatusBadRequest, "idempotency_key_required", "an Agent outbound review requires a valid idempotency key")
		}
		intentDigest := outboundpolicy.Digest(intent)
		idempotencyKey := scopedOutboundIdempotencyKey(a.acc.ID(), requestKey)
		draft, err := saveOutboundPolicyDraft(ctx, a.acc, raw, store.OutboundPolicyDraft{
			Status:         "pending_confirmation",
			DraftVersion:   1,
			PolicyVersion:  decision.PolicyVersion,
			Reasons:        policyReasons(decision.Reasons),
			Source:         intent.Source,
			SourceEmailID:  numericEmailID(intent.SourceEmailID),
			ContentDigest:  append([]byte(nil), intentDigest[:]...),
			IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			var statusErr *statusError
			if errors.As(err, &statusErr) {
				return statusErr
			}
			return internalErr("policy_draft_failed", err)
		}
		info := outboundPolicyProjection(draft, intent.Subject)
		return &statusError{
			status: http.StatusConflict,
			code:   "outbound_review_required",
			msg:    "email was not sent; owner review is required",
			policy: info,
		}
	default:
		return internalErr("outbound_policy_invalid", fmt.Errorf("unsupported policy outcome %q", decision.Outcome))
	}
}

func saveOutboundPolicyDraft(ctx context.Context, acc store.Account, raw []byte, draft store.OutboundPolicyDraft) (store.OutboundPolicyDraft, error) {
	err := acc.Tx(ctx, func(tx store.Tx) error {
		policyTx, ok := tx.(store.OutboundPolicyDraftTx)
		if !ok {
			return fmt.Errorf("outbound policy draft transaction capability unavailable")
		}
		existing, found, err := policyTx.FindOutboundPolicyDraftByIdempotencyKey(draft.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(existing.ContentDigest, draft.ContentDigest) {
				return errStatus(http.StatusConflict, "idempotency_key_conflict", "idempotency key was already used for different review content")
			}
			draft = existing
			return nil
		}

		mailboxes, err := tx.QueryMailbox().List()
		if err != nil {
			return err
		}
		var mailbox *store.Mailbox
		for i := range mailboxes {
			if mailboxes[i].Draft {
				mailbox = &mailboxes[i]
				break
			}
		}
		if mailbox == nil {
			mailbox, err = acc.MailboxFind(tx, "Drafts")
			if err != nil {
				return err
			}
		}
		if mailbox == nil {
			created, _, err := acc.MailboxEnsure(tx, "Drafts", true, store.SpecialUse{Draft: true}, nil)
			if err != nil {
				return err
			}
			mailbox = &created
		} else if !mailbox.Draft {
			specialUse := mailbox.SpecialUse
			specialUse.Draft = true
			if _, err := acc.MailboxSetSpecialUse(tx, mailbox, specialUse); err != nil {
				return err
			}
		}

		message := &store.Message{}
		message.Flags.Draft = true
		if _, err := acc.MessageAdd(tx, mailbox, message, memBlob(raw), store.AddOpts{}); err != nil {
			return err
		}
		draft.EmailID = message.EffectiveEmailID()
		return policyTx.PutOutboundPolicyDraft(draft)
	})
	if err != nil {
		return store.OutboundPolicyDraft{}, err
	}
	return draft, nil
}

func scopedOutboundIdempotencyKey(accountID int64, requestKey string) string {
	digest := sha256.Sum256([]byte(strconv.FormatInt(accountID, 10) + "\x00" + requestKey))
	return hex.EncodeToString(digest[:])
}

func numericEmailID(id string) int64 {
	value, ok := parseEmailID(id)
	if !ok {
		return 0
	}
	return value
}

func policyReasons(reasons []outboundpolicy.Reason) []store.OutboundPolicyReason {
	out := make([]store.OutboundPolicyReason, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, store.OutboundPolicyReason{
			Code: reason.Code, Title: reason.Title, Description: reason.Description,
		})
	}
	return out
}

func outboundPolicyProjection(draft store.OutboundPolicyDraft, subject string) outboundPolicyInfo {
	info := outboundPolicyInfo{
		Outcome: outboundpolicy.OutcomeOwnerReviewRequired, Status: draft.Status,
		DraftVersion: draft.DraftVersion, PolicyVersion: draft.PolicyVersion,
		Reasons: draft.Reasons, Source: draft.Source,
		DraftID: "E" + strconv.FormatInt(draft.EmailID, 10), DraftSubject: subject,
	}
	if draft.SourceEmailID > 0 {
		info.SourceEmailID = "E" + strconv.FormatInt(draft.SourceEmailID, 10)
	}
	return info
}
