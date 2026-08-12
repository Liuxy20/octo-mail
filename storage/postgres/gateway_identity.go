package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/jackc/pgx/v5"
)

const gatewayAssertionNonceRetention = 5 * time.Minute

// ConsumeGatewayAssertionNonce atomically rejects replay across all octo-mail
// instances. Expired rows are reclaimed opportunistically on authenticated
// gateway traffic.
func (d *Directory) ConsumeGatewayAssertionNonce(ctx context.Context, issuer, nonce string, expiresAt, now time.Time) error {
	issuer = strings.TrimSpace(issuer)
	nonce = strings.TrimSpace(nonce)
	now = now.UTC()
	if issuer == "" || nonce == "" || now.IsZero() || !expiresAt.After(now) {
		return fmt.Errorf("invalid gateway assertion nonce")
	}
	// Keep consumed nonces beyond their signed expiry so a faster node cannot
	// delete replay evidence while a slower node would still accept the token.
	cleanupBefore := now.Add(-gatewayAssertionNonceRetention)
	command, err := d.s.Pool.Exec(ctx,
		`WITH cleanup AS (
		   DELETE FROM gateway_assertion_nonces WHERE expires_at <= $4
		 )
		 INSERT INTO gateway_assertion_nonces (issuer, nonce, expires_at)
		 VALUES ($1,$2,$3)
		 ON CONFLICT DO NOTHING`,
		issuer, nonce, expiresAt.UTC(), cleanupBefore)
	if err != nil {
		return fmt.Errorf("consume gateway assertion nonce: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("gateway assertion replayed")
	}
	return nil
}

// AuthenticateGatewayIdentity resolves an exact provisioned OCTO actor and
// Space binding. There is deliberately no subject-only or Space fallback.
func (d *Directory) AuthenticateGatewayIdentity(ctx context.Context, issuer, subject, spaceID string, selectedAccountID int64) (directory.TenantScope, directory.Principal, int64, error) {
	fail := fmt.Errorf("authentication failed")
	issuer = strings.TrimSpace(issuer)
	subject = strings.TrimSpace(subject)
	spaceID = strings.TrimSpace(spaceID)
	if issuer == "" || subject == "" || spaceID == "" || selectedAccountID < 0 {
		return nil, directory.Principal{}, 0, fail
	}
	var principal directory.Principal
	var defaultAccountID int64
	err := d.s.Pool.QueryRow(ctx,
		`SELECT p.id,p.tenant_id,p.login,g.default_account_id
		 FROM gateway_identities g
		 JOIN principals p ON p.id=g.owner_principal_id AND p.tenant_id=g.tenant_id
		 JOIN accounts a ON a.id=g.default_account_id AND a.tenant_id=g.tenant_id
		                    AND a.owner_principal_id=p.id AND NOT a.disabled
		 WHERE g.issuer=$1 AND g.subject=$2 AND g.space_id=$3 AND NOT g.disabled`,
		issuer, subject, spaceID).Scan(&principal.ID, &principal.TenantID, &principal.Login, &defaultAccountID)
	if err == pgx.ErrNoRows {
		return nil, directory.Principal{}, 0, fail
	}
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	accountID := defaultAccountID
	if selectedAccountID > 0 {
		accountID = selectedAccountID
		var owned bool
		if err := d.s.Pool.QueryRow(ctx,
			`SELECT EXISTS(
			   SELECT 1 FROM accounts acc
			   WHERE acc.id=$1 AND acc.tenant_id=$2 AND acc.owner_principal_id=$3
			     AND NOT acc.disabled
			     AND (
			       acc.id=$4 OR EXISTS (
			         SELECT 1 FROM agent_mailbox_registrations registration
			         WHERE registration.account_id=acc.id
			           AND registration.tenant_id=acc.tenant_id
			           AND registration.owner_principal_id=acc.owner_principal_id
			           AND registration.space_id=$5
			       )
			     )
			 )`,
			accountID, principal.TenantID, principal.ID, defaultAccountID, spaceID).Scan(&owned); err != nil {
			return nil, directory.Principal{}, 0, err
		}
		if !owned {
			return nil, directory.Principal{}, 0, fail
		}
	}
	scope, err := d.tenantScope(ctx, principal.TenantID)
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	return scope, principal, accountID, nil
}
