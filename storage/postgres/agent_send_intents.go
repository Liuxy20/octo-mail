package postgres

import (
	"context"
	"fmt"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

func (a *account) ClaimAgentSendIntent(ctx context.Context, key string, contentDigest []byte) (store.AgentSendIntent, bool, error) {
	command, err := a.s.Pool.Exec(ctx,
		`INSERT INTO agent_send_intents (account_id,idempotency_key,content_digest)
		 VALUES ($1,$2,$3) ON CONFLICT (account_id,idempotency_key) DO NOTHING`,
		a.id, key, contentDigest)
	if err != nil {
		return store.AgentSendIntent{}, false, fmt.Errorf("claim Agent send intent: %w", err)
	}
	intent, err := a.agentSendIntent(ctx, key)
	if err != nil {
		return store.AgentSendIntent{}, false, err
	}
	return intent, command.RowsAffected() == 1, nil
}

func (a *account) CompleteAgentSendIntent(ctx context.Context, key string, messageID int64, submissionIDs []int64) error {
	command, err := a.s.Pool.Exec(ctx,
		`UPDATE agent_send_intents
		 SET status='accepted',message_id=$3,submission_ids=$4,updated_at=now()
		 WHERE account_id=$1 AND idempotency_key=$2 AND status='processing'`,
		a.id, key, messageID, submissionIDs)
	if err != nil {
		return fmt.Errorf("complete Agent send intent: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("complete Agent send intent: processing claim not found")
	}
	return nil
}

func (a *account) AbandonAgentSendIntent(ctx context.Context, key string) error {
	_, err := a.s.Pool.Exec(ctx,
		`DELETE FROM agent_send_intents
		 WHERE account_id=$1 AND idempotency_key=$2 AND status='processing'`,
		a.id, key)
	if err != nil {
		return fmt.Errorf("abandon Agent send intent: %w", err)
	}
	return nil
}

func (a *account) agentSendIntent(ctx context.Context, key string) (store.AgentSendIntent, error) {
	var intent store.AgentSendIntent
	err := a.s.Pool.QueryRow(ctx,
		`SELECT idempotency_key,content_digest,status,COALESCE(message_id,0),
		        submission_ids,created_at,updated_at
		 FROM agent_send_intents WHERE account_id=$1 AND idempotency_key=$2`,
		a.id, key).Scan(
		&intent.IdempotencyKey, &intent.ContentDigest, &intent.Status,
		&intent.MessageID, &intent.SubmissionIDs, &intent.CreatedAt, &intent.UpdatedAt,
	)
	if err != nil {
		return store.AgentSendIntent{}, fmt.Errorf("read Agent send intent: %w", err)
	}
	return intent, nil
}

var _ store.AgentSendIntentStore = (*account)(nil)
