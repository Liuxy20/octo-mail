package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

const gatewayProvisioningAccountPrefix = "gateway-owner:"

// EnsureGatewayIdentity idempotently provisions the human owner account used
// by browser Agent Mail. The configured domain is the tenant selector; no
// caller-supplied database id crosses this trust boundary.
func (d *Directory) EnsureGatewayIdentity(ctx context.Context, input directory.GatewayProvisioningInput) (directory.GatewayProvisioningResult, error) {
	input.Issuer = strings.TrimSpace(input.Issuer)
	input.Subject = strings.TrimSpace(input.Subject)
	input.SpaceID = strings.TrimSpace(input.SpaceID)
	input.Localpart = strings.ToLower(strings.TrimSpace(input.Localpart))
	input.Domain = strings.ToLower(strings.TrimSpace(input.Domain))
	if input.Issuer == "" || input.Subject == "" || input.SpaceID == "" ||
		len(input.Issuer) > 200 || len(input.Subject) > 300 || len(input.SpaceID) > 300 {
		return directory.GatewayProvisioningResult{}, directory.ErrGatewayProvisioningConflict
	}

	tx, err := d.s.Pool.Begin(ctx)
	if err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("begin gateway provisioning: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds

	if existing, found, err := gatewayProvisioningIdentity(ctx, tx, input.Issuer, input.Subject, input.SpaceID); err != nil {
		return directory.GatewayProvisioningResult{}, err
	} else if found {
		return existing, nil
	}
	// Existing exact bindings remain usable in the historical empty-domain
	// compatibility mode. Only a genuinely new identity requires the configured
	// provisioning domain and a valid preferred address.
	if !validGatewayLocalpart(input.Localpart) {
		return directory.GatewayProvisioningResult{}, directory.ErrInvalidLocalpart
	}
	if input.Domain == "" {
		return directory.GatewayProvisioningResult{}, directory.ErrAgentMailboxDomainNotFound
	}

	// First-use provisioning is rare. Locking the configured domain is a simple
	// cross-instance serialization point that also makes address allocation and
	// exact gateway binding publication atomic without a process-local lock.
	var tenantID, domainID int64
	if err := tx.QueryRow(ctx,
		`SELECT tenant_id,id FROM domains WHERE domain=$1 AND NOT disabled FOR UPDATE`,
		input.Domain).Scan(&tenantID, &domainID); errors.Is(err, pgx.ErrNoRows) {
		return directory.GatewayProvisioningResult{}, directory.ErrAgentMailboxDomainNotFound
	} else if err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("lock gateway provisioning domain: %w", err)
	}

	// Another instance may have completed this exact identity while this
	// transaction waited for the domain row.
	if existing, found, err := gatewayProvisioningIdentity(ctx, tx, input.Issuer, input.Subject, input.SpaceID); err != nil {
		return directory.GatewayProvisioningResult{}, err
	} else if found {
		return existing, nil
	}

	// The exact issuer+subject+Space key is the isolation root. A single OCTO
	// user in two Spaces receives distinct principals/accounts, matching the
	// existing AuthenticateGatewayIdentity no-fallback contract.
	localpart, err := availableGatewayLocalpart(ctx, tx, tenantID, domainID, input.Domain, input.Localpart, input.Issuer, input.Subject, input.SpaceID)
	if err != nil {
		return directory.GatewayProvisioningResult{}, err
	}
	address := localpart + "@" + input.Domain
	ownerDigest := sha256.Sum256([]byte(input.Issuer + "\x00" + input.Subject + "\x00" + input.SpaceID))
	accountName := gatewayProvisioningAccountPrefix + hex.EncodeToString(ownerDigest[:16])

	var principalID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,$2) RETURNING id`,
		tenantID, address).Scan(&principalID); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("create gateway owner principal: %w", err)
	}
	var accountID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$2,$3) RETURNING id`,
		tenantID, principalID, accountName).Scan(&accountID); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("create gateway owner account: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart,is_alias)
		 VALUES ($1,$2,$3,$4,false)`,
		tenantID, domainID, accountID, localpart); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("create gateway owner address: %w", err)
	}

	// Reuse the normal mailbox writer used by CreateAgentMailbox so the Inbox
	// projection and changelog are born in sync. The account is not published by
	// a gateway identity until this transaction commits, so no account writer can
	// race this initialization.
	account := d.s.openAccount(accountID, tenantID, accountName)
	mailboxTx := &pgTx{ctx: ctx, tx: tx, acc: account, write: true}
	if _, err := mailboxTx.ensureMailbox("Inbox", true, store.SpecialUse{}); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("create gateway owner Inbox: %w", err)
	}
	if err := mailboxTx.flush(); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("initialize gateway owner changelog: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		input.Issuer, input.Subject, input.SpaceID, tenantID, principalID, accountID); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("create gateway identity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return directory.GatewayProvisioningResult{}, fmt.Errorf("commit gateway provisioning: %w", err)
	}
	return directory.GatewayProvisioningResult{
		TenantID: tenantID, PrincipalID: principalID, DefaultAccountID: accountID,
		Address: address, Created: true,
	}, nil
}

func validGatewayLocalpart(localpart string) bool {
	return aliasLocalpartPattern.MatchString(localpart) && !strings.Contains(localpart, "..")
}

func gatewayProvisioningIdentity(ctx context.Context, tx pgx.Tx, issuer, subject, spaceID string) (directory.GatewayProvisioningResult, bool, error) {
	var result directory.GatewayProvisioningResult
	var gatewayDisabled, accountDisabled bool
	err := tx.QueryRow(ctx,
		`SELECT g.tenant_id,g.owner_principal_id,g.default_account_id,
		        g.disabled,COALESCE(acc.disabled,true),COALESCE(addr.localpart || '@' || dom.domain,'')
		 FROM gateway_identities g
		 LEFT JOIN accounts acc ON acc.id=g.default_account_id AND acc.tenant_id=g.tenant_id
		                       AND acc.owner_principal_id=g.owner_principal_id
		 LEFT JOIN LATERAL (
		   SELECT a.localpart,a.domain_id FROM addresses a
		   WHERE a.account_id=acc.id AND a.tenant_id=acc.tenant_id AND NOT a.is_alias
		   ORDER BY a.id LIMIT 1
		 ) addr ON true
		 LEFT JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=g.tenant_id
		 WHERE g.issuer=$1 AND g.subject=$2 AND g.space_id=$3`,
		issuer, subject, spaceID).Scan(
		&result.TenantID, &result.PrincipalID, &result.DefaultAccountID,
		&gatewayDisabled, &accountDisabled, &result.Address)
	if errors.Is(err, pgx.ErrNoRows) {
		return directory.GatewayProvisioningResult{}, false, nil
	}
	if err != nil {
		return directory.GatewayProvisioningResult{}, false, fmt.Errorf("find gateway identity: %w", err)
	}
	if gatewayDisabled {
		return directory.GatewayProvisioningResult{}, false, directory.ErrGatewayIdentityDisabled
	}
	if accountDisabled || result.Address == "" {
		return directory.GatewayProvisioningResult{}, false, directory.ErrGatewayProvisioningConflict
	}
	return result, true, nil
}

func availableGatewayLocalpart(ctx context.Context, tx pgx.Tx, tenantID, domainID int64, domain, preferred, issuer, subject, spaceID string) (string, error) {
	candidates := []string{preferred, suffixedGatewayLocalpart(preferred, issuer, subject, spaceID)}
	for _, candidate := range candidates {
		var occupied bool
		login := candidate + "@" + domain
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(
			   SELECT 1 FROM addresses WHERE tenant_id=$1 AND domain_id=$2 AND localpart=$3
			   UNION ALL
			   SELECT 1 FROM principals WHERE login=$4
			 )`, tenantID, domainID, candidate, login).Scan(&occupied); err != nil {
			return "", fmt.Errorf("check gateway owner address: %w", err)
		}
		if !occupied {
			return candidate, nil
		}
	}
	return "", directory.ErrGatewayProvisioningConflict
}

func suffixedGatewayLocalpart(preferred, issuer, subject, spaceID string) string {
	digest := sha256.Sum256([]byte(issuer + "\x00" + subject + "\x00" + spaceID))
	suffix := hex.EncodeToString(digest[:5])
	base := preferred
	if len(base) > 52 {
		base = base[:52]
	}
	base = strings.TrimRight(base, "._-")
	return base + "-" + suffix
}
