package webapi

import (
	"context"
	"net/http"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

const cleanupTimeout = 5 * time.Second

func cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
}

func resultUnknownStatusError(code, message string, cause error) *statusError {
	return &statusError{
		status: http.StatusConflict,
		code:   code,
		msg:    message,
		cause:  cause,
	}
}

func submissionResultUnknownError(cause error) *statusError {
	return resultUnknownStatusError(
		"submission_result_unknown",
		"the submission result is unknown; inspect Sent and do not retry automatically",
		cause,
	)
}

type deliverySummary struct {
	Status    string `json:"status"`
	Delivered int    `json:"delivered"`
	Total     int    `json:"total"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type deliveryRecipient struct {
	Address         string `json:"address"`
	Status          string `json:"status"`
	ReasonCode      string `json:"reasonCode,omitempty"`
	TechnicalDetail string `json:"technicalDetail,omitempty"`
	LastAttemptAt   string `json:"lastAttemptAt,omitempty"`
	DeliveredAt     string `json:"deliveredAt,omitempty"`
}

func customerDeliveryStatus(status string) string {
	switch status {
	case "delivered":
		return "delivered"
	case "failed":
		return "not_delivered"
	default:
		return "sending"
	}
}

func summarizeDelivery(items []store.OutboundDelivery) *deliverySummary {
	if len(items) == 0 {
		return nil
	}
	delivered, failed := 0, 0
	var updated time.Time
	for _, item := range items {
		switch item.Status {
		case "delivered":
			delivered++
		case "failed":
			failed++
		}
		if item.UpdatedAt.After(updated) {
			updated = item.UpdatedAt
		}
	}
	status := "sending"
	if delivered == len(items) {
		status = "delivered"
	} else if failed == len(items) {
		status = "not_delivered"
	} else if delivered+failed == len(items) && delivered > 0 && failed > 0 {
		status = "partially_delivered"
	}
	summary := &deliverySummary{Status: status, Delivered: delivered, Total: len(items)}
	if !updated.IsZero() {
		summary.UpdatedAt = updated.UTC().Format(time.RFC3339)
	}
	return summary
}

func recipientDelivery(item store.OutboundDelivery) deliveryRecipient {
	result := deliveryRecipient{
		Address: item.Recipient, Status: customerDeliveryStatus(item.Status),
		ReasonCode: item.ReasonCode, TechnicalDetail: item.TechnicalDetail,
	}
	if !item.LastAttemptAt.IsZero() {
		result.LastAttemptAt = item.LastAttemptAt.UTC().Format(time.RFC3339)
	}
	if !item.DeliveredAt.IsZero() {
		result.DeliveredAt = item.DeliveredAt.UTC().Format(time.RFC3339)
	}
	return result
}

func outboundStore(acc store.Account) (store.OutboundDeliveryStore, error) {
	tracked, ok := acc.(store.OutboundDeliveryStore)
	if !ok {
		return nil, errStatus(http.StatusNotImplemented, "delivery_tracking_unavailable", "delivery tracking not available")
	}
	return tracked, nil
}

func saveSentCopy(ctx context.Context, acc store.Account, raw []byte) (store.Message, error) {
	m := store.Message{}
	m.Flags.Seen = true
	err := acc.Tx(ctx, func(tx store.Tx) error {
		mailboxes, err := tx.QueryMailbox().List()
		if err != nil {
			return err
		}
		var mb *store.Mailbox
		for i := range mailboxes {
			if mailboxes[i].Sent {
				mb = &mailboxes[i]
				break
			}
		}
		if mb == nil {
			mb, err = acc.MailboxFind(tx, "Sent")
			if err != nil {
				return err
			}
		}
		if mb == nil {
			created, _, e := acc.MailboxEnsure(tx, "Sent", true, store.SpecialUse{Sent: true}, nil)
			if e != nil {
				return e
			}
			mb = &created
		} else if !mb.Sent {
			su := mb.SpecialUse
			su.Sent = true
			if _, err := acc.MailboxSetSpecialUse(tx, mb, su); err != nil {
				return err
			}
		}
		_, err = acc.MessageAdd(tx, mb, &m, memBlob(raw), store.AddOpts{})
		return err
	})
	return m, err
}

func removeSentCopy(ctx context.Context, acc store.Account, messageID int64) error {
	return acc.Tx(ctx, func(tx store.Tx) error {
		messages, err := acc.MessagesByEmailID(tx, messageID)
		if err != nil {
			return err
		}
		for _, message := range messages {
			mb, err := mailboxByID(tx, acc, message.MailboxID)
			if err != nil {
				return err
			}
			if _, _, err := acc.MessageRemove(tx, 0, mb, store.RemoveOpts{Expunge: true}, message); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) cleanupFailedSubmissionSentCopy(ctx context.Context, acc store.Account, messageID int64) {
	cleanupCtx, cancel := cleanupContext(ctx)
	defer cancel()
	if err := removeSentCopy(cleanupCtx, acc, messageID); err != nil && s.Log != nil {
		s.Log.WarnContext(cleanupCtx, "failed submission Sent cleanup failed", "message_id", messageID, "err", err)
	}
}

// GET /webapi/v0/messages/{id}/delivery
func (s *Server) getMessageDelivery(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	messageID, ok := parseEmailID(id)
	if !ok {
		return 0, nil, errStatus(http.StatusBadRequest, "invalid_id", "invalid message id")
	}
	if err := a.acc.ReadTx(ctx, func(tx store.Tx) error {
		_, err := loadGroup(tx, a.acc, id)
		return err
	}); err != nil {
		return 0, nil, err
	}
	tracked, err := outboundStore(a.acc)
	if err != nil {
		return 0, nil, err
	}
	items, err := tracked.OutboundDeliveries(ctx, messageID)
	if err != nil {
		return 0, nil, err
	}
	summary := summarizeDelivery(items)
	if summary == nil {
		return 0, nil, errStatus(http.StatusNotFound, "not_found", "no delivery result for message")
	}
	recipients := make([]deliveryRecipient, 0, len(items))
	for _, item := range items {
		recipients = append(recipients, recipientDelivery(item))
	}
	return http.StatusOK, map[string]any{
		"messageId": id, "status": summary.Status,
		"delivered": summary.Delivered, "total": summary.Total,
		"updatedAt": summary.UpdatedAt, "recipients": recipients,
	}, nil
}

// GET /webapi/v0/identity
func (s *Server) getIdentity(ctx context.Context, a authCtx, r *http.Request) (int, any, error) {
	return http.StatusOK, map[string]any{"address": a.login}, nil
}
