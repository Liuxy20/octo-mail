package postgres

import (
	"context"
	"database/sql"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

// OutboundDeliveries returns the durable per-recipient delivery projection for
// one Sent message. account_id is always part of the predicate so PostgreSQL
// prunes to the account partition and the store capability boundary is kept.
func (a *account) OutboundDeliveries(ctx context.Context, messageID int64) ([]store.OutboundDelivery, error) {
	grouped, err := a.OutboundDeliveriesForMessages(ctx, []int64{messageID})
	if err != nil {
		return nil, err
	}
	return grouped[messageID], nil
}

// OutboundDeliveriesForMessages batch-loads list-view delivery summaries
// without issuing one query per Sent message.
func (a *account) OutboundDeliveriesForMessages(ctx context.Context, messageIDs []int64) (map[int64][]store.OutboundDelivery, error) {
	out := make(map[int64][]store.OutboundDelivery)
	if len(messageIDs) == 0 {
		return out, nil
	}
	rows, err := a.s.Pool.Query(ctx,
		`SELECT queue_id, message_id, recipient, status, attempt_count,
		        smtp_code, smtp_secode, reason_code, technical_detail,
		        created_at, last_attempt_at, delivered_at, failed_at, updated_at
		 FROM outbound_deliveries
		 WHERE account_id=$1 AND message_id = ANY($2)
		 ORDER BY message_id, queue_id`,
		a.id, messageIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var d store.OutboundDelivery
		var lastAttempt, delivered, failed sql.NullTime
		if err := rows.Scan(
			&d.QueueID, &d.MessageID, &d.Recipient, &d.Status, &d.AttemptCount,
			&d.SMTPCode, &d.SMTPSecode, &d.ReasonCode, &d.TechnicalDetail,
			&d.CreatedAt, &lastAttempt, &delivered, &failed, &d.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if lastAttempt.Valid {
			d.LastAttemptAt = lastAttempt.Time
		}
		if delivered.Valid {
			d.DeliveredAt = delivered.Time
		}
		if failed.Valid {
			d.FailedAt = failed.Time
		}
		out[d.MessageID] = append(out[d.MessageID], d)
	}
	return out, rows.Err()
}
