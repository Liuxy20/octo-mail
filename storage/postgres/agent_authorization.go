package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/security/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	agentAuthorizationLifetime = 10 * time.Minute
	agentAuthorizationInterval = 3
)

func (d *Directory) CreateAgentAuthorization(ctx context.Context, input directory.AgentAuthorizationInput) (directory.AgentDeviceAuthorization, error) {
	input.BotID = strings.TrimSpace(input.BotID)
	input.BotProfile = strings.TrimSpace(input.BotProfile)
	input.ClientName = strings.TrimSpace(input.ClientName)
	input.SpaceID = strings.TrimSpace(input.SpaceID)
	if input.BotID == "" {
		return directory.AgentDeviceAuthorization{}, fmt.Errorf("bot id is required")
	}
	if input.SpaceID == "" {
		return directory.AgentDeviceAuthorization{}, fmt.Errorf("space id is required")
	}
	if len(input.BotID) > 200 || len(input.BotProfile) > 200 || len(input.ClientName) > 200 || len(input.SpaceID) > 200 {
		return directory.AgentDeviceAuthorization{}, fmt.Errorf("agent authorization metadata is too long")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(input.CodeChallenge)
	if err != nil || len(challenge) != sha256.Size {
		return directory.AgentDeviceAuthorization{}, fmt.Errorf("invalid code challenge")
	}
	if _, err := d.s.Pool.Exec(ctx,
		`DELETE FROM agent_auth_requests WHERE expires_at < now() - interval '1 day'`); err != nil {
		return directory.AgentDeviceAuthorization{}, fmt.Errorf("cleanup expired agent authorizations: %w", err)
	}

	deviceCode, err := randomURLToken("omd_", 32)
	if err != nil {
		return directory.AgentDeviceAuthorization{}, err
	}
	deviceHash := sha256.Sum256([]byte(deviceCode))
	expiresAt := time.Now().UTC().Add(agentAuthorizationLifetime)

	for attempt := 0; attempt < 5; attempt++ {
		userCode, err := randomUserCode()
		if err != nil {
			return directory.AgentDeviceAuthorization{}, err
		}
		_, err = d.s.Pool.Exec(ctx,
			`INSERT INTO agent_auth_requests
			 (device_hash,user_code,bot_id,bot_profile,client_name,space_id,code_challenge,expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			deviceHash[:], userCode, input.BotID, input.BotProfile, input.ClientName, input.SpaceID, input.CodeChallenge, expiresAt)
		if err == nil {
			return directory.AgentDeviceAuthorization{
				DeviceCode: deviceCode,
				UserCode:   userCode,
				ExpiresIn:  int(agentAuthorizationLifetime.Seconds()),
				Interval:   agentAuthorizationInterval,
			}, nil
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return directory.AgentDeviceAuthorization{}, fmt.Errorf("create agent authorization: %w", err)
		}
	}
	return directory.AgentDeviceAuthorization{}, fmt.Errorf("create agent authorization: user code collision")
}

func (d *Directory) AgentAuthorization(ctx context.Context, ownerPrincipalID int64, spaceID, userCode string) (directory.AgentAuthorization, error) {
	userCode = normalizeUserCode(userCode)
	spaceID = strings.TrimSpace(spaceID)
	var (
		out              directory.AgentAuthorization
		owner            *int64
		created, expires time.Time
	)
	var outboundMode string
	err := d.s.Pool.QueryRow(ctx,
		`SELECT user_code,bot_id,bot_profile,client_name,space_id,status,owner_principal_id,created_at,expires_at,outbound_mode
		 FROM agent_auth_requests WHERE user_code=$1`, userCode).
		Scan(&out.UserCode, &out.BotID, &out.BotProfile, &out.ClientName, &out.SpaceID, &out.Status, &owner, &created, &expires, &outboundMode)
	if err == pgx.ErrNoRows || (err == nil && owner != nil && *owner != ownerPrincipalID) {
		return directory.AgentAuthorization{}, directory.ErrAuthorizationNotFound
	}
	if err != nil {
		return directory.AgentAuthorization{}, err
	}
	if spaceID == "" || out.SpaceID == "" || out.SpaceID != spaceID {
		return directory.AgentAuthorization{}, directory.ErrAuthorizationSpaceMismatch
	}
	if time.Now().After(expires) && out.Status != "exchanged" {
		return directory.AgentAuthorization{}, directory.ErrAuthorizationExpired
	}
	out.RequestedAt = created.UTC().Format(time.RFC3339)
	out.ExpiresAt = expires.UTC().Format(time.RFC3339)
	out.PollIntervalSeconds = agentAuthorizationInterval
	out.OutboundMode = directory.AgentOutboundMode(outboundMode)
	return out, nil
}

func (d *Directory) ApproveAgentAuthorization(ctx context.Context, ownerPrincipalID int64, spaceID, userCode string, accountID int64, outboundMode directory.AgentOutboundMode) error {
	if !outboundMode.Valid() {
		return fmt.Errorf("invalid Agent outbound mode %q", outboundMode)
	}
	spaceID = strings.TrimSpace(spaceID)
	tx, err := d.s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless committed

	var status, requestSpaceID string
	var expires time.Time
	var approvedOutboundMode string
	var approvedOwner, approvedAccount *int64
	err = tx.QueryRow(ctx,
		`SELECT status,space_id,expires_at,owner_principal_id,account_id,outbound_mode
		 FROM agent_auth_requests WHERE user_code=$1 FOR UPDATE`, normalizeUserCode(userCode)).
		Scan(&status, &requestSpaceID, &expires, &approvedOwner, &approvedAccount, &approvedOutboundMode)
	if err == pgx.ErrNoRows {
		return directory.ErrAuthorizationNotFound
	}
	if err != nil {
		return err
	}
	if spaceID == "" || requestSpaceID == "" || requestSpaceID != spaceID {
		return directory.ErrAuthorizationSpaceMismatch
	}
	if time.Now().After(expires) {
		return directory.ErrAuthorizationExpired
	}
	if status == "approved" && approvedOwner != nil && approvedAccount != nil &&
		*approvedOwner == ownerPrincipalID && *approvedAccount == accountID && approvedOutboundMode == string(outboundMode) {
		return tx.Commit(ctx)
	}
	if status != "pending" {
		return directory.ErrAuthorizationUsed
	}

	var owned bool
	err = tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM accounts acc
		   WHERE acc.id=$1 AND acc.owner_principal_id=$2 AND NOT acc.disabled
		     AND EXISTS (
		         SELECT 1 FROM agent_mailbox_registrations registration
		         WHERE registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		           AND registration.owner_principal_id=acc.owner_principal_id
		           AND registration.space_id=$3
		     )
		     AND NOT EXISTS (
		         SELECT 1 FROM gateway_identities gateway
		         WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		           AND gateway.owner_principal_id=acc.owner_principal_id
		           AND gateway.space_id=$3 AND NOT gateway.disabled
		     )
		 )`, accountID, ownerPrincipalID, spaceID).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return directory.ErrMailboxNotFound
	}

	_, err = tx.Exec(ctx,
		`UPDATE agent_auth_requests
		 SET status='approved',owner_principal_id=$2,account_id=$3,
		     outbound_mode=$4,auto_reply_enabled=($4='automatic_send'),approved_at=now()
		 WHERE user_code=$1`, normalizeUserCode(userCode), ownerPrincipalID, accountID, string(outboundMode))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Directory) ExchangeAgentAuthorization(ctx context.Context, deviceCode, codeVerifier string) (directory.AgentAuthorizationCredential, error) {
	if !strings.HasPrefix(deviceCode, "omd_") || codeVerifier == "" {
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationNotFound
	}
	deviceHash := sha256.Sum256([]byte(deviceCode))
	verifierHash := sha256.Sum256([]byte(codeVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])

	tx, err := d.s.Pool.Begin(ctx)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless committed

	var (
		status, challenge, botID, botProfile, clientName, spaceID string
		ownerPrincipalID, accountID                               *int64
		expires                                                   time.Time
		outboundMode                                              string
	)
	err = tx.QueryRow(ctx,
		`SELECT status,code_challenge,bot_id,bot_profile,client_name,space_id,
		        owner_principal_id,account_id,expires_at,outbound_mode
		 FROM agent_auth_requests WHERE device_hash=$1 FOR UPDATE`, deviceHash[:]).
		Scan(&status, &challenge, &botID, &botProfile, &clientName, &spaceID, &ownerPrincipalID, &accountID, &expires, &outboundMode)
	if err == pgx.ErrNoRows {
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationNotFound
	}
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	if time.Now().After(expires) {
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationExpired
	}
	if challenge != wantChallenge {
		return directory.AgentAuthorizationCredential{}, directory.ErrInvalidCodeVerifier
	}
	switch status {
	case "pending":
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationPending
	case "denied":
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationDenied
	case "exchanged":
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationUsed
	case "approved":
		if ownerPrincipalID == nil || accountID == nil || strings.TrimSpace(spaceID) == "" {
			return directory.AgentAuthorizationCredential{}, fmt.Errorf("approved authorization has no mailbox")
		}
	default:
		return directory.AgentAuthorizationCredential{}, directory.ErrAuthorizationUsed
	}

	var tenantID int64
	var address string
	err = tx.QueryRow(ctx,
		`SELECT acc.tenant_id,addr.localpart || '@' || dom.domain
		 FROM accounts acc
		 JOIN addresses addr ON addr.account_id=acc.id AND addr.tenant_id=acc.tenant_id AND NOT addr.is_alias
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 JOIN agent_mailbox_registrations registration
		   ON registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		  AND registration.owner_principal_id=acc.owner_principal_id
		  AND registration.space_id=$3
		 WHERE acc.id=$1 AND acc.owner_principal_id=$2 AND NOT acc.disabled
		   AND NOT EXISTS (
		     SELECT 1 FROM gateway_identities gateway
		     WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		       AND gateway.owner_principal_id=acc.owner_principal_id
		       AND gateway.space_id=$3 AND NOT gateway.disabled
		   )`,
		*accountID, *ownerPrincipalID, spaceID).Scan(&tenantID, &address)
	if err == pgx.ErrNoRows {
		return directory.AgentAuthorizationCredential{}, directory.ErrMailboxNotFound
	}
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}

	// Rebinding is atomic: revoke the previous binding and every credential
	// before inserting the new active binding inside the same transaction.
	_, err = tx.Exec(ctx,
		`UPDATE agent_binding_credentials SET revoked_at=now()
		 WHERE revoked_at IS NULL AND binding_id IN (
		   SELECT id FROM agent_bindings WHERE account_id=$1 AND status='active'
		 )`, *accountID)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	_, err = tx.Exec(ctx,
		`UPDATE agent_bindings SET status='revoked',revoked_at=now()
		 WHERE account_id=$1 AND status='active'`, *accountID)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}

	var bindingID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO agent_bindings
		 (tenant_id,account_id,owner_principal_id,space_id,bot_id,bot_profile,client_name,outbound_mode,auto_reply_enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,($8='automatic_send')) RETURNING id`,
		tenantID, *accountID, *ownerPrincipalID, spaceID, botID, botProfile, clientName, outboundMode).Scan(&bindingID)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}

	prefix, secret, err := newAPIKeyToken()
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	hashed, err := auth.HashAPIKey(secret)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	credJSON, err := hashed.Marshal()
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO agent_binding_credentials (binding_id,key_prefix,cred)
		 VALUES ($1,$2,$3)`, bindingID, prefix, credJSON)
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	_, err = tx.Exec(ctx,
		`UPDATE agent_auth_requests SET status='exchanged',exchanged_at=now()
		 WHERE device_hash=$1`, deviceHash[:])
	if err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return directory.AgentAuthorizationCredential{}, err
	}
	return directory.AgentAuthorizationCredential{
		AccessToken: "omb_" + prefix + "_" + secret,
		Address:     address, BotID: botID, BotProfile: botProfile,
		OutboundMode: directory.AgentOutboundMode(outboundMode),
	}, nil
}

func (d *Directory) RevokeAgentBinding(ctx context.Context, ownerPrincipalID, accountID int64, spaceID string) error {
	spaceID = strings.TrimSpace(spaceID)
	if spaceID == "" {
		return directory.ErrAuthorizationSpaceMismatch
	}
	tx, err := d.s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless committed
	var owned bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM accounts acc
		   JOIN agent_mailbox_registrations registration
		     ON registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		    AND registration.owner_principal_id=acc.owner_principal_id
		    AND registration.space_id=$3
		   WHERE acc.id=$1 AND acc.owner_principal_id=$2 AND NOT acc.disabled
		     AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		         AND gateway.owner_principal_id=acc.owner_principal_id
		         AND gateway.space_id=$3 AND NOT gateway.disabled
		     )
		 )`,
		accountID, ownerPrincipalID, spaceID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return directory.ErrMailboxNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_binding_credentials SET revoked_at=now()
		 WHERE revoked_at IS NULL AND binding_id IN (
		   SELECT id FROM agent_bindings
		   WHERE account_id=$1 AND owner_principal_id=$2 AND space_id=$3 AND status='active'
		 )`, accountID, ownerPrincipalID, spaceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_bindings SET status='revoked',revoked_at=now()
		 WHERE account_id=$1 AND owner_principal_id=$2 AND space_id=$3 AND status='active'`,
		accountID, ownerPrincipalID, spaceID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Directory) SetAgentOutboundMode(ctx context.Context, ownerPrincipalID, accountID int64, spaceID string, mode directory.AgentOutboundMode) error {
	if ownerPrincipalID <= 0 || accountID <= 0 {
		return directory.ErrMailboxNotFound
	}
	spaceID = strings.TrimSpace(spaceID)
	if spaceID == "" {
		return directory.ErrAuthorizationSpaceMismatch
	}
	if !mode.Valid() {
		return fmt.Errorf("invalid Agent outbound mode %q", mode)
	}
	tx, err := d.s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless committed

	var owned bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(
		   SELECT 1 FROM accounts acc
		   JOIN agent_mailbox_registrations registration
		     ON registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		    AND registration.owner_principal_id=acc.owner_principal_id
		    AND registration.space_id=$3
		   WHERE acc.id=$1 AND acc.owner_principal_id=$2 AND NOT acc.disabled
		     AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		         AND gateway.owner_principal_id=acc.owner_principal_id
		         AND gateway.space_id=$3 AND NOT gateway.disabled
		     )
		 )`, accountID, ownerPrincipalID, spaceID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return directory.ErrMailboxNotFound
	}
	command, err := tx.Exec(ctx,
		`UPDATE agent_bindings
		 SET outbound_mode=$4,auto_reply_enabled=($4='automatic_send')
		 WHERE account_id=$1 AND owner_principal_id=$2 AND space_id=$3 AND status='active'`,
		accountID, ownerPrincipalID, spaceID, string(mode))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return directory.ErrAgentBindingNotFound
	}
	return tx.Commit(ctx)
}

func (d *Directory) AuthenticateAgentCredential(ctx context.Context, token string) (directory.TenantScope, directory.Principal, int64, int64, error) {
	fail := fmt.Errorf("authentication failed")
	prefix, secret, ok := parseAgentCredential(token)
	if !ok {
		return nil, directory.Principal{}, 0, 0, fail
	}
	var (
		credentialID, bindingID, tenantID, accountID, principalID int64
		login                                                     string
		credJSON                                                  []byte
	)
	err := d.s.Pool.QueryRow(ctx,
		`SELECT c.id,b.id,b.tenant_id,b.account_id,p.id,p.login,c.cred
		 FROM agent_binding_credentials c
		 JOIN agent_bindings b ON b.id=c.binding_id AND b.status='active'
		 JOIN accounts acc ON acc.id=b.account_id AND acc.tenant_id=b.tenant_id AND NOT acc.disabled
		 JOIN principals p ON p.id=acc.principal_id AND p.tenant_id=acc.tenant_id
		 WHERE c.key_prefix=$1 AND c.revoked_at IS NULL AND b.space_id <> ''
		   AND EXISTS (
		       SELECT 1 FROM agent_mailbox_registrations registration
		       WHERE registration.account_id=b.account_id AND registration.tenant_id=b.tenant_id
		         AND registration.owner_principal_id=b.owner_principal_id
		         AND registration.space_id=b.space_id
		   )
		   AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=b.account_id AND gateway.tenant_id=b.tenant_id
		         AND gateway.owner_principal_id=b.owner_principal_id
		         AND gateway.space_id=b.space_id AND NOT gateway.disabled
		   )`, prefix).
		Scan(&credentialID, &bindingID, &tenantID, &accountID, &principalID, &login, &credJSON)
	if err == pgx.ErrNoRows {
		auth.VerifyAPIKeyDummy(secret)
		return nil, directory.Principal{}, 0, 0, fail
	}
	if err != nil {
		return nil, directory.Principal{}, 0, 0, err
	}
	if !auth.VerifyAPIKey(credJSON, secret) {
		return nil, directory.Principal{}, 0, 0, fail
	}
	scope, err := d.tenantScope(ctx, tenantID)
	if err != nil {
		return nil, directory.Principal{}, 0, 0, err
	}
	_, _ = d.s.Pool.Exec(ctx,
		`UPDATE agent_binding_credentials SET last_used_at=now() WHERE id=$1`, credentialID)
	_, _ = d.s.Pool.Exec(ctx,
		`UPDATE agent_bindings SET last_used_at=now() WHERE id=$1`, bindingID)
	return scope, directory.Principal{ID: principalID, TenantID: tenantID, Login: login}, accountID, credentialID, nil
}

func (d *Directory) AgentAutomationAllowed(ctx context.Context, credentialID int64, operation string) (bool, error) {
	if credentialID <= 0 || strings.TrimSpace(operation) == "" {
		return false, nil
	}
	var outboundMode string
	err := d.s.Pool.QueryRow(ctx,
		`SELECT b.outbound_mode
		 FROM agent_binding_credentials c
		 JOIN agent_bindings b ON b.id=c.binding_id AND b.status='active'
		 WHERE c.id=$1 AND c.revoked_at IS NULL AND b.space_id <> ''
		   AND EXISTS (
		       SELECT 1 FROM agent_mailbox_registrations registration
		       WHERE registration.account_id=b.account_id AND registration.tenant_id=b.tenant_id
		         AND registration.owner_principal_id=b.owner_principal_id
		         AND registration.space_id=b.space_id
		   )
		   AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=b.account_id AND gateway.tenant_id=b.tenant_id
		         AND gateway.owner_principal_id=b.owner_principal_id
		         AND gateway.space_id=b.space_id AND NOT gateway.disabled
		   )`, credentialID).
		Scan(&outboundMode)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if operation == "mail.draft.send" {
		return outboundMode == string(directory.AgentOutboundModeManualConfirmation), nil
	}
	return outboundMode == string(directory.AgentOutboundModeAutomaticSend) &&
		(operation == "mail.message.send" || operation == "mail.message.reply"), nil
}

func randomURLToken(prefix string, size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func randomUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}

func normalizeUserCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func parseAgentCredential(token string) (prefix, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, "omb_")
	if !found {
		return "", "", false
	}
	prefix, secret, found = strings.Cut(rest, "_")
	return prefix, secret, found && prefix != "" && secret != ""
}

var _ directory.AgentAuthorizationDirectory = (*Directory)(nil)
