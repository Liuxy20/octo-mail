package postgres

import (
	"context"
	"fmt"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/jackc/pgx/v5"
)

func (pt *pgTx) ClaimDraftSend(emailID int64, draftVersion int, contentDigest []byte) (store.DraftSendClaim, bool, error) {
	command, err := pt.tx.Exec(pt.ctx,
		`INSERT INTO draft_send_claims (account_id,email_id,draft_version,content_digest)
		 VALUES ($1,$2,$3,$4) ON CONFLICT (account_id,email_id) DO NOTHING`,
		pt.acc.id, emailID, draftVersion, contentDigest)
	if err != nil {
		return store.DraftSendClaim{}, false, fmt.Errorf("claim Draft send: %w", err)
	}
	claim, err := scanDraftSendClaim(pt.tx.QueryRow(pt.ctx,
		`SELECT email_id,draft_version,content_digest,status,COALESCE(message_id,0),
		        submission_ids,created_at,updated_at
		 FROM draft_send_claims WHERE account_id=$1 AND email_id=$2`,
		pt.acc.id, emailID))
	if err != nil {
		return store.DraftSendClaim{}, false, fmt.Errorf("read Draft send claim: %w", err)
	}
	return claim, command.RowsAffected() == 1, nil
}

func (a *account) CompleteDraftSendClaim(ctx context.Context, emailID int64, messageID int64, submissionIDs []int64) error {
	command, err := a.s.Pool.Exec(ctx,
		`UPDATE draft_send_claims
		 SET status='accepted',message_id=$3,submission_ids=$4,updated_at=now()
		 WHERE account_id=$1 AND email_id=$2 AND status='processing'`,
		a.id, emailID, messageID, submissionIDs)
	if err != nil {
		return fmt.Errorf("complete Draft send claim: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("complete Draft send claim: processing claim not found")
	}
	return nil
}

func (a *account) AbandonDraftSendClaim(ctx context.Context, emailID int64) error {
	_, err := a.s.Pool.Exec(ctx,
		`DELETE FROM draft_send_claims
		 WHERE account_id=$1 AND email_id=$2 AND status='processing'`,
		a.id, emailID)
	if err != nil {
		return fmt.Errorf("abandon Draft send claim: %w", err)
	}
	return nil
}

func (a *account) DeleteDraftSendClaim(ctx context.Context, emailID int64) error {
	_, err := a.s.Pool.Exec(ctx,
		`DELETE FROM draft_send_claims WHERE account_id=$1 AND email_id=$2 AND status='accepted'`,
		a.id, emailID)
	if err != nil {
		return fmt.Errorf("delete Draft send claim: %w", err)
	}
	return nil
}

func scanDraftSendClaim(row pgx.Row) (store.DraftSendClaim, error) {
	var claim store.DraftSendClaim
	err := row.Scan(
		&claim.EmailID, &claim.DraftVersion, &claim.ContentDigest, &claim.Status,
		&claim.MessageID, &claim.SubmissionIDs, &claim.CreatedAt, &claim.UpdatedAt,
	)
	return claim, err
}

var _ store.DraftSendClaimTx = (*pgTx)(nil)
var _ store.DraftSendClaimStore = (*account)(nil)
