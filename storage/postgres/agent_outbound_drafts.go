package postgres

import (
	"context"
	"fmt"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/jackc/pgx/v5"
)

func (pt *pgTx) FindAgentOutboundDraftByIdempotencyKey(key string) (store.AgentOutboundDraft, bool, error) {
	draft, err := scanAgentOutboundDraft(pt.tx.QueryRow(pt.ctx,
		`SELECT email_id,draft_type,status,draft_version,source_email_id,
		        content_digest,idempotency_key,created_at,updated_at
		 FROM agent_outbound_drafts
		 WHERE account_id=$1 AND idempotency_key=$2`, pt.acc.id, key))
	if err == pgx.ErrNoRows {
		return store.AgentOutboundDraft{}, false, nil
	}
	if err != nil {
		return store.AgentOutboundDraft{}, false, fmt.Errorf("find agent outbound draft: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) FindAgentOutboundDraftByEmailID(emailID int64) (store.AgentOutboundDraft, bool, error) {
	draft, err := scanAgentOutboundDraft(pt.tx.QueryRow(pt.ctx,
		`SELECT email_id,draft_type,status,draft_version,source_email_id,
		        content_digest,idempotency_key,created_at,updated_at
		 FROM agent_outbound_drafts
		 WHERE account_id=$1 AND email_id=$2`, pt.acc.id, emailID))
	if err == pgx.ErrNoRows {
		return store.AgentOutboundDraft{}, false, nil
	}
	if err != nil {
		return store.AgentOutboundDraft{}, false, fmt.Errorf("find agent outbound draft by email id: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) PutAgentOutboundDraft(draft store.AgentOutboundDraft) error {
	var sourceEmailID any
	if draft.SourceEmailID > 0 {
		sourceEmailID = draft.SourceEmailID
	}
	_, err := pt.tx.Exec(pt.ctx,
		`INSERT INTO agent_outbound_drafts
		 (account_id,email_id,draft_type,status,draft_version,source_email_id,
		  content_digest,idempotency_key)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		pt.acc.id, draft.EmailID, draft.DraftType, draft.Status,
		draft.DraftVersion, sourceEmailID, draft.ContentDigest,
		draft.IdempotencyKey)
	if err != nil {
		return fmt.Errorf("insert agent outbound draft: %w", err)
	}
	return nil
}

func (pt *pgTx) ReplaceAgentOutboundDraft(oldEmailID int64, expectedVersion int, newEmailID int64, contentDigest []byte) (store.AgentOutboundDraft, bool, error) {
	draft, err := scanAgentOutboundDraft(pt.tx.QueryRow(pt.ctx,
		`UPDATE agent_outbound_drafts
		 SET email_id=$4,draft_version=draft_version+1,content_digest=$5,updated_at=now()
		 WHERE account_id=$1 AND email_id=$2 AND draft_version=$3
		 RETURNING email_id,draft_type,status,draft_version,source_email_id,
		           content_digest,idempotency_key,created_at,updated_at`,
		pt.acc.id, oldEmailID, expectedVersion, newEmailID, contentDigest))
	if err == pgx.ErrNoRows {
		return store.AgentOutboundDraft{}, false, nil
	}
	if err != nil {
		return store.AgentOutboundDraft{}, false, fmt.Errorf("replace agent outbound draft: %w", err)
	}
	return draft, true, nil
}

func (pt *pgTx) DeleteAgentOutboundDraft(emailID int64) error {
	if _, err := pt.tx.Exec(pt.ctx,
		`DELETE FROM agent_outbound_drafts WHERE account_id=$1 AND email_id=$2`,
		pt.acc.id, emailID); err != nil {
		return fmt.Errorf("delete agent outbound draft: %w", err)
	}
	return nil
}

func (a *account) AgentOutboundDraftsForMessages(ctx context.Context, messageIDs []int64) (map[int64]store.AgentOutboundDraft, error) {
	out := make(map[int64]store.AgentOutboundDraft)
	if len(messageIDs) == 0 {
		return out, nil
	}
	rows, err := a.s.Pool.Query(ctx,
		`SELECT email_id,draft_type,status,draft_version,source_email_id,
		        content_digest,idempotency_key,created_at,updated_at
		 FROM agent_outbound_drafts
		 WHERE account_id=$1 AND email_id=ANY($2)`, a.id, messageIDs)
	if err != nil {
		return nil, fmt.Errorf("list agent outbound drafts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		draft, err := scanAgentOutboundDraft(rows)
		if err != nil {
			return nil, fmt.Errorf("scan agent outbound draft: %w", err)
		}
		out[draft.EmailID] = draft
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list agent outbound drafts: %w", err)
	}
	return out, nil
}

func scanAgentOutboundDraft(row rowScanner) (store.AgentOutboundDraft, error) {
	var draft store.AgentOutboundDraft
	var sourceEmailID *int64
	err := row.Scan(
		&draft.EmailID, &draft.DraftType, &draft.Status, &draft.DraftVersion,
		&sourceEmailID, &draft.ContentDigest, &draft.IdempotencyKey,
		&draft.CreatedAt, &draft.UpdatedAt,
	)
	if err != nil {
		return store.AgentOutboundDraft{}, err
	}
	if sourceEmailID != nil {
		draft.SourceEmailID = *sourceEmailID
	}
	return draft, nil
}

var _ store.AgentOutboundDraftTx = (*pgTx)(nil)
var _ store.AgentOutboundDraftStore = (*account)(nil)
