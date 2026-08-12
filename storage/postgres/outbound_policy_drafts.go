package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/jackc/pgx/v5"
)

func (pt *pgTx) FindOutboundPolicyDraftByIdempotencyKey(key string) (store.OutboundPolicyDraft, bool, error) {
	draft, err := scanOutboundPolicyDraft(pt.tx.QueryRow(pt.ctx,
		`SELECT email_id,status,draft_version,policy_version,reasons,source,
		        source_email_id,content_digest,idempotency_key,created_at,updated_at
		 FROM outbound_policy_drafts
		 WHERE account_id=$1 AND idempotency_key=$2`, pt.acc.id, key))
	if err == pgx.ErrNoRows {
		return store.OutboundPolicyDraft{}, false, nil
	}
	if err != nil {
		return store.OutboundPolicyDraft{}, false, fmt.Errorf("find outbound policy draft: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) FindOutboundPolicyDraftByEmailID(emailID int64) (store.OutboundPolicyDraft, bool, error) {
	draft, err := scanOutboundPolicyDraft(pt.tx.QueryRow(pt.ctx,
		`SELECT email_id,status,draft_version,policy_version,reasons,source,
		        source_email_id,content_digest,idempotency_key,created_at,updated_at
		 FROM outbound_policy_drafts
		 WHERE account_id=$1 AND email_id=$2`, pt.acc.id, emailID))
	if err == pgx.ErrNoRows {
		return store.OutboundPolicyDraft{}, false, nil
	}
	if err != nil {
		return store.OutboundPolicyDraft{}, false, fmt.Errorf("find outbound policy draft by email id: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) PutOutboundPolicyDraft(draft store.OutboundPolicyDraft) error {
	reasons, err := json.Marshal(draft.Reasons)
	if err != nil {
		return fmt.Errorf("encode outbound policy reasons: %w", err)
	}
	var sourceEmailID any
	if draft.SourceEmailID > 0 {
		sourceEmailID = draft.SourceEmailID
	}
	_, err = pt.tx.Exec(pt.ctx,
		`INSERT INTO outbound_policy_drafts
		 (account_id,email_id,status,draft_version,policy_version,reasons,source,
		  source_email_id,content_digest,idempotency_key)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		pt.acc.id, draft.EmailID, draft.Status, draft.DraftVersion,
		draft.PolicyVersion, reasons, draft.Source, sourceEmailID,
		draft.ContentDigest, draft.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("insert outbound policy draft: %w", err)
	}
	return nil
}

func (pt *pgTx) ReplaceOutboundPolicyDraft(oldEmailID int64, expectedVersion int, newEmailID int64, contentDigest []byte) (store.OutboundPolicyDraft, bool, error) {
	draft, err := scanOutboundPolicyDraft(pt.tx.QueryRow(pt.ctx,
		`UPDATE outbound_policy_drafts
		 SET email_id=$4,draft_version=draft_version+1,content_digest=$5,updated_at=now()
		 WHERE account_id=$1 AND email_id=$2 AND draft_version=$3
		 RETURNING email_id,status,draft_version,policy_version,reasons,source,
		           source_email_id,content_digest,idempotency_key,created_at,updated_at`,
		pt.acc.id, oldEmailID, expectedVersion, newEmailID, contentDigest))
	if err == pgx.ErrNoRows {
		return store.OutboundPolicyDraft{}, false, nil
	}
	if err != nil {
		return store.OutboundPolicyDraft{}, false, fmt.Errorf("replace outbound policy draft: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) DeleteOutboundPolicyDraft(emailID int64) error {
	if _, err := pt.tx.Exec(pt.ctx,
		`DELETE FROM outbound_policy_drafts WHERE account_id=$1 AND email_id=$2`,
		pt.acc.id, emailID); err != nil {
		return fmt.Errorf("delete outbound policy draft: %w", err)
	}
	return nil
}

func (a *account) OutboundPolicyDraftsForMessages(ctx context.Context, messageIDs []int64) (map[int64]store.OutboundPolicyDraft, error) {
	out := make(map[int64]store.OutboundPolicyDraft)
	if len(messageIDs) == 0 {
		return out, nil
	}
	rows, err := a.s.Pool.Query(ctx,
		`SELECT email_id,status,draft_version,policy_version,reasons,source,
		        source_email_id,content_digest,idempotency_key,created_at,updated_at
		 FROM outbound_policy_drafts
		 WHERE account_id=$1 AND email_id=ANY($2)`, a.id, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("list outbound policy drafts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		draft, err := scanOutboundPolicyDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("scan outbound policy draft: %w", err)
		}
		out[draft.EmailID] = draft
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list outbound policy drafts: %w", err)
	}
	return out, nil
}

func scanOutboundPolicyDraft(row rowScanner) (store.OutboundPolicyDraft, error) {
	var draft store.OutboundPolicyDraft
	var reasons []byte
	var sourceEmailID *int64
	err := row.Scan(
		&draft.EmailID, &draft.Status, &draft.DraftVersion, &draft.PolicyVersion,
		&reasons, &draft.Source, &sourceEmailID, &draft.ContentDigest,
		&draft.IdempotencyKey, &draft.CreatedAt, &draft.UpdatedAt,
	)
	if err != nil {
		return store.OutboundPolicyDraft{}, err
	}
	if sourceEmailID != nil {
		draft.SourceEmailID = *sourceEmailID
	}
	if err := json.Unmarshal(reasons, &draft.Reasons); err != nil {
		return store.OutboundPolicyDraft{}, fmt.Errorf("decode outbound policy reasons: %w", err)
	}
	return draft, nil
}

var _ store.OutboundPolicyDraftTx = (*pgTx)(nil)
var _ store.OutboundPolicyDraftStore = (*account)(nil)
