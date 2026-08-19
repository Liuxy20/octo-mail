package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/security/auth"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

var aliasLocalpartPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)

// Compile-time assertions that the Postgres impls satisfy the kernel interfaces.
var (
	_ store.Account           = (*account)(nil)
	_ store.Tx                = (*pgTx)(nil)
	_ directory.Directory     = (*Directory)(nil)
	_ directory.TenantScope   = (*tenantScope)(nil)
	_ directory.InboundTarget = (*inboundTarget)(nil)
)

// Directory is the Postgres-backed identity object graph. It is the only way to
// obtain account handles; tenant isolation is structural (you navigate from a
// TenantScope, never by global id).
type Directory struct {
	s *Store
}

// NewDirectory returns the directory backed by the store.
func (s *Store) NewDirectory() *Directory { return &Directory{s: s} }

// OpenAccountForOps returns a read/write account handle for operator tasks
// (backup/restore, maintenance) by tenant name + account name. It is NOT part of
// the tenant-isolation capability graph — it is a privileged, out-of-band
// accessor for the octo-mail CLI running with DB credentials, never exposed to a
// network principal.
func (s *Store) OpenAccountForOps(ctx context.Context, tenant, account string) (store.Account, error) {
	var tenantID, accID int64
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE name=$1`, tenant).Scan(&tenantID); err != nil {
		return nil, fmt.Errorf("tenant %q: %w", tenant, err)
	}
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM accounts WHERE tenant_id=$1 AND name=$2`, tenantID, account).Scan(&accID); err != nil {
		return nil, fmt.Errorf("account %q: %w", account, err)
	}
	return s.openAccount(accID, tenantID, account), nil
}

// openAccount constructs an account handle. Package-internal: callers reach it
// only via a TenantScope or InboundTarget, never directly by id.
func (s *Store) openAccount(id, tenantID int64, name string) *account {
	return &account{s: s, id: id, tenantID: tenantID, name: name}
}

func (d *Directory) AuthenticatePrincipal(ctx context.Context, login string, cred directory.Credential) (directory.TenantScope, directory.Principal, error) {
	fail := fmt.Errorf("authentication failed")
	var p directory.Principal
	var credJSON []byte
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, login, cred FROM principals WHERE login=$1`, login).
		Scan(&p.ID, &p.TenantID, &p.Login, &credJSON)
	if err == pgx.ErrNoRows {
		// Spend the same argon2 cost on a missing login as on an existing one, so
		// response timing can't be used to enumerate valid logins. Only for the
		// password credential (the nil/resolve-only path is internal, not network).
		if c, ok := cred.(directory.PasswordCredential); ok {
			auth.VerifyDummy(string(c))
		}
		return nil, directory.Principal{}, fail
	}
	if err != nil {
		return nil, directory.Principal{}, err
	}

	// Verify the credential. A nil credential means "resolve only" — permitted
	// solely for trusted internal callers, never for a network principal. Network
	// entry points (imapd/smtpd/jmapd) always pass a directory.PasswordCredential.
	switch c := cred.(type) {
	case directory.PasswordCredential:
		if !auth.Verify(credJSON, string(c)) {
			return nil, directory.Principal{}, fail
		}
	case nil:
		// resolve-only (internal). Left for trusted callers; do not expose.
	default:
		return nil, directory.Principal{}, fail
	}

	ts, err := d.tenantScope(ctx, p.TenantID)
	if err != nil {
		return nil, directory.Principal{}, err
	}
	return ts, p, nil
}

// LookupSCRAM returns the stored SCRAM-SHA-256 verifier for a login, so the
// protocol layer can drive the SASL exchange. Errors (including no such
// principal or no SCRAM verifier stored) are returned uniformly to avoid
// leaking which logins exist.
func (d *Directory) LookupSCRAM(ctx context.Context, login string) (directory.SCRAMVerifier, error) {
	fail := fmt.Errorf("authentication failed")
	var credJSON []byte
	err := d.s.Pool.QueryRow(ctx, `SELECT cred FROM principals WHERE login=$1`, login).Scan(&credJSON)
	if err == pgx.ErrNoRows {
		return directory.SCRAMVerifier{}, fail
	}
	if err != nil {
		return directory.SCRAMVerifier{}, err
	}
	salt, saltedPwd, iters, ok := auth.SCRAMVerifier(credJSON)
	if !ok {
		return directory.SCRAMVerifier{}, fail
	}
	return directory.SCRAMVerifier{Salt: salt, SaltedPassword: saltedPwd, Iterations: iters}, nil
}

// ScopeForLogin returns the tenant scope for a login WITHOUT any credential
// check. It is only called by the protocol layer after a SCRAM proof has already
// verified the client; it must never be exposed as an authentication bypass.
func (d *Directory) ScopeForLogin(ctx context.Context, login string) (directory.TenantScope, directory.Principal, error) {
	var p directory.Principal
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, login FROM principals WHERE login=$1`, login).
		Scan(&p.ID, &p.TenantID, &p.Login)
	if err == pgx.ErrNoRows {
		return nil, directory.Principal{}, fmt.Errorf("no such principal")
	}
	if err != nil {
		return nil, directory.Principal{}, err
	}
	ts, err := d.tenantScope(ctx, p.TenantID)
	if err != nil {
		return nil, directory.Principal{}, err
	}
	return ts, p, nil
}

// SetPassword sets/updates a principal's password (argon2id). Used by admin/
// provisioning and tests.
func (d *Directory) SetPassword(ctx context.Context, login, password string) error {
	c, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	credJSON, err := c.Marshal()
	if err != nil {
		return err
	}
	ct, err := d.s.Pool.Exec(ctx, `UPDATE principals SET cred=$2 WHERE login=$1`, login, credJSON)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("no such principal %q", login)
	}
	return nil
}

// IssueAPIKey mints an account-scoped API key for a login and stores a hash of
// its secret half. The full token (omk_<prefix>_<secret>) is returned once and
// never recoverable afterward. login must be an email address that maps to an
// account (the address the key will act as).
func (d *Directory) IssueAPIKey(ctx context.Context, login, name string) (string, error) {
	if name == "" {
		name = "api key"
	}
	var principalID, tenantID int64
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id FROM principals WHERE login=$1`, login).Scan(&principalID, &tenantID)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("no such principal %q", login)
	}
	if err != nil {
		return "", err
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return "", fmt.Errorf("login must be an email address: %w", err)
	}
	var accountID int64
	err = d.s.Pool.QueryRow(ctx,
		`SELECT a.account_id
		 FROM addresses a
		 JOIN domains dom ON dom.id = a.domain_id
		 WHERE a.tenant_id=$1 AND dom.domain=$2 AND a.localpart=$3`,
		tenantID, addr.Domain.Name(), string(addr.Localpart)).Scan(&accountID)
	if err == pgx.ErrNoRows {
		return "", fmt.Errorf("no account for address %q", login)
	}
	if err != nil {
		return "", err
	}

	prefix, secret, err := newAPIKeyToken()
	if err != nil {
		return "", err
	}
	cred, err := auth.HashAPIKey(secret)
	if err != nil {
		return "", err
	}
	credJSON, err := cred.Marshal()
	if err != nil {
		return "", err
	}
	if _, err := d.s.Pool.Exec(ctx,
		`INSERT INTO api_keys (tenant_id, account_id, login, name, key_prefix, cred)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, accountID, login, name, prefix, credJSON); err != nil {
		return "", err
	}
	return "omk_" + prefix + "_" + secret, nil
}

// AuthenticateAPIKey verifies a bearer API key and returns the tenant scope,
// principal, and account id it acts as. Token form omk_<prefix>_<secret>: lookup
// by the indexed prefix among non-revoked keys, then constant-time verify the
// secret. Failure is uniform (does not leak key existence).
func (d *Directory) AuthenticateAPIKey(ctx context.Context, token string) (directory.TenantScope, directory.Principal, int64, error) {
	fail := fmt.Errorf("authentication failed")
	prefix, secret, ok := parseAPIKeyToken(token)
	if !ok {
		return nil, directory.Principal{}, 0, fail
	}
	var (
		keyID, tenantID, accountID int64
		login                      string
		credJSON                   []byte
	)
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, account_id, login, cred FROM api_keys
		 WHERE key_prefix=$1 AND revoked_at IS NULL`, prefix).
		Scan(&keyID, &tenantID, &accountID, &login, &credJSON)
	if err == pgx.ErrNoRows {
		// Match the cost of a real verify so an unknown key prefix can't be
		// distinguished by timing.
		auth.VerifyAPIKeyDummy(secret)
		return nil, directory.Principal{}, 0, fail
	}
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	if !auth.VerifyAPIKey(credJSON, secret) {
		return nil, directory.Principal{}, 0, fail
	}
	ts, err := d.tenantScope(ctx, tenantID)
	if err != nil {
		return nil, directory.Principal{}, 0, err
	}
	_, _ = d.s.Pool.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id=$1`, keyID)
	var principalID int64
	if err := d.s.Pool.QueryRow(ctx,
		`SELECT id FROM principals WHERE tenant_id=$1 AND login=$2`,
		tenantID, login).Scan(&principalID); err != nil {
		return nil, directory.Principal{}, 0, err
	}
	return ts, directory.Principal{ID: principalID, TenantID: tenantID, Login: login}, accountID, nil
}

// newAPIKeyToken generates a random (prefix, secret) pair: prefix is a short
// public lookup selector, secret is the high-entropy half that is hashed.
func newAPIKeyToken() (prefix, secret string, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 24) // 192-bit secret
	if _, err = rand.Read(pb); err != nil {
		return "", "", err
	}
	if _, err = rand.Read(sb); err != nil {
		return "", "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(pb)), strings.ToLower(enc.EncodeToString(sb)), nil
}

// parseAPIKeyToken splits an omk_<prefix>_<secret> token.
func parseAPIKeyToken(token string) (prefix, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, "omk_")
	if !found {
		return "", "", false
	}
	prefix, secret, found = strings.Cut(rest, "_")
	if !found || prefix == "" || secret == "" {
		return "", "", false
	}
	return prefix, secret, true
}

func (d *Directory) tenantScope(ctx context.Context, tenantID int64) (*tenantScope, error) {
	var ti directory.TenantInfo
	var quota *int64
	err := d.s.Pool.QueryRow(ctx,
		`SELECT id, name, quota_bytes FROM tenants WHERE id=$1`, tenantID).
		Scan(&ti.ID, &ti.Name, &quota)
	if err != nil {
		return nil, err
	}
	if quota != nil {
		ti.QuotaBytes = *quota
	}
	return &tenantScope{s: d.s, info: ti}, nil
}

// ResolveInbound is the only unauthenticated resolver: domain -> tenant ->
// account, returning a delivery-only handle.
func (d *Directory) ResolveInbound(ctx context.Context, addr smtp.Path) (directory.InboundTarget, error) {
	var accID, tenantID int64
	var isAlias bool
	err := d.s.Pool.QueryRow(ctx,
		`SELECT a.account_id, a.tenant_id, a.is_alias
		 FROM addresses a
		 JOIN domains d ON d.id = a.domain_id
		 JOIN accounts acc ON acc.id=a.account_id AND acc.tenant_id=a.tenant_id
		 WHERE d.domain=$1 AND a.localpart=$2 AND NOT d.disabled AND NOT acc.disabled`,
		addr.IPDomain.Domain.Name(), string(addr.Localpart)).
		Scan(&accID, &tenantID, &isAlias)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such recipient")
	}
	if err != nil {
		return nil, err
	}
	var name string
	if err := d.s.Pool.QueryRow(ctx, `SELECT name FROM accounts WHERE id=$1`, accID).Scan(&name); err != nil {
		return nil, err
	}
	var quota *int64
	var tname string
	_ = d.s.Pool.QueryRow(ctx, `SELECT name, quota_bytes FROM tenants WHERE id=$1`, tenantID).Scan(&tname, &quota)
	ti := directory.TenantInfo{ID: tenantID, Name: tname}
	if quota != nil {
		ti.QuotaBytes = *quota
	}
	return &inboundTarget{acc: d.s.openAccount(accID, tenantID, name), tenant: ti, isAlias: isAlias}, nil
}

// tenantScope is a capability bound to one tenant.
type tenantScope struct {
	s    *Store
	info directory.TenantInfo
}

func (t *tenantScope) Tenant() directory.TenantInfo { return t.info }

func (t *tenantScope) Account(ctx context.Context, name string) (store.Account, error) {
	var id int64
	err := t.s.Pool.QueryRow(ctx,
		`SELECT id FROM accounts WHERE tenant_id=$1 AND name=$2 AND NOT disabled`, t.info.ID, name).Scan(&id)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such account")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(id, t.info.ID, name), nil
}

// AccountForAddress resolves a tenant-owned email address to its account.
func (t *tenantScope) AccountForAddress(ctx context.Context, addr smtp.Path) (store.Account, error) {
	var accID int64
	var name string
	err := t.s.Pool.QueryRow(ctx,
		`SELECT a.account_id, acc.name
		 FROM addresses a
		 JOIN domains d ON d.id = a.domain_id
		 JOIN accounts acc ON acc.id = a.account_id AND NOT acc.disabled
		 WHERE a.tenant_id=$1 AND d.domain=$2 AND a.localpart=$3`,
		t.info.ID, addr.IPDomain.Domain.Name(), string(addr.Localpart)).Scan(&accID, &name)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no account for address")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(accID, t.info.ID, name), nil
}

// AccountForID resolves an account by id within this tenant. The WHERE clause
// pins tenant_id, so an id from another tenant returns no row — isolation is
// structural, not a caller convention.
func (t *tenantScope) AccountForID(ctx context.Context, id int64) (store.Account, error) {
	var name string
	err := t.s.Pool.QueryRow(ctx,
		`SELECT name FROM accounts WHERE id=$1 AND tenant_id=$2 AND NOT disabled`, id, t.info.ID).Scan(&name)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("no such account")
	}
	if err != nil {
		return nil, err
	}
	return t.s.openAccount(id, t.info.ID, name), nil
}

func (t *tenantScope) AccountAddresses(ctx context.Context, accountID int64) ([]directory.MailAddress, error) {
	rows, err := t.s.Pool.Query(ctx,
		`SELECT a.id, a.localpart || '@' || d.domain, NOT a.is_alias
		 FROM addresses a
		 JOIN domains d ON d.id=a.domain_id AND d.tenant_id=a.tenant_id
		 WHERE a.tenant_id=$1 AND a.account_id=$2
		 ORDER BY a.is_alias, a.id`,
		t.info.ID, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account addresses: %w", err)
	}
	defer rows.Close()
	var addresses []directory.MailAddress
	for rows.Next() {
		var address directory.MailAddress
		if err := rows.Scan(&address.ID, &address.Address, &address.Primary); err != nil {
			return nil, fmt.Errorf("scan account address: %w", err)
		}
		addresses = append(addresses, address)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list account addresses: %w", err)
	}
	return addresses, nil
}

func (t *tenantScope) CreateAccountAlias(ctx context.Context, accountID int64, localpart string) (directory.MailAddress, error) {
	localpart = strings.ToLower(strings.TrimSpace(localpart))
	if !aliasLocalpartPattern.MatchString(localpart) || strings.Contains(localpart, "..") {
		return directory.MailAddress{}, directory.ErrInvalidLocalpart
	}
	var domainID int64
	var domainName string
	err := t.s.Pool.QueryRow(ctx,
		`SELECT a.domain_id, d.domain
		 FROM addresses a
		 JOIN domains d ON d.id=a.domain_id AND d.tenant_id=a.tenant_id
		 JOIN accounts acc ON acc.id=a.account_id AND acc.tenant_id=a.tenant_id
		 WHERE a.tenant_id=$1 AND a.account_id=$2 AND NOT a.is_alias
		 ORDER BY a.id
		 LIMIT 1`,
		t.info.ID, accountID).Scan(&domainID, &domainName)
	if err == pgx.ErrNoRows {
		return directory.MailAddress{}, directory.ErrAddressNotFound
	}
	if err != nil {
		return directory.MailAddress{}, fmt.Errorf("find primary address: %w", err)
	}
	var address directory.MailAddress
	err = t.s.Pool.QueryRow(ctx,
		`INSERT INTO addresses (tenant_id, domain_id, account_id, localpart, is_alias)
		 VALUES ($1,$2,$3,$4,true)
		 ON CONFLICT (domain_id, localpart) DO NOTHING
		 RETURNING id`,
		t.info.ID, domainID, accountID, localpart).Scan(&address.ID)
	if err == pgx.ErrNoRows {
		return directory.MailAddress{}, directory.ErrAddressExists
	}
	if err != nil {
		return directory.MailAddress{}, fmt.Errorf("create account alias: %w", err)
	}
	address.Address = localpart + "@" + domainName
	return address, nil
}

func (t *tenantScope) DeleteAccountAlias(ctx context.Context, accountID, addressID int64) error {
	var isAlias bool
	err := t.s.Pool.QueryRow(ctx,
		`SELECT is_alias FROM addresses
		 WHERE tenant_id=$1 AND account_id=$2 AND id=$3`,
		t.info.ID, accountID, addressID).Scan(&isAlias)
	if err == pgx.ErrNoRows {
		return directory.ErrAddressNotFound
	}
	if err != nil {
		return fmt.Errorf("find account alias: %w", err)
	}
	if !isAlias {
		return directory.ErrPrimaryAddress
	}
	ct, err := t.s.Pool.Exec(ctx,
		`DELETE FROM addresses WHERE tenant_id=$1 AND account_id=$2 AND id=$3 AND is_alias`,
		t.info.ID, accountID, addressID)
	if err != nil {
		return fmt.Errorf("delete account alias: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return directory.ErrAddressNotFound
	}
	return nil
}

func (t *tenantScope) AgentMailboxes(ctx context.Context, principalID int64, spaceID string) ([]directory.AgentMailbox, error) {
	spaceID = strings.TrimSpace(spaceID)
	if spaceID == "" {
		return nil, directory.ErrAuthorizationSpaceMismatch
	}
	rows, err := t.s.Pool.Query(ctx,
		`SELECT acc.id, addr.localpart || '@' || dom.domain,
		        COALESCE(binding.bot_id,''),COALESCE(binding.bot_profile,''),
		        CASE WHEN binding.id IS NULL THEN 'unconnected' ELSE 'connected' END,
		        COALESCE(binding.outbound_mode,'manual_confirmation'),
		        NOT EXISTS (
		          SELECT 1 FROM gateway_identities gateway_default
		          WHERE gateway_default.default_account_id=acc.id
		            AND gateway_default.tenant_id=acc.tenant_id
		            AND gateway_default.owner_principal_id=acc.owner_principal_id
		            AND NOT gateway_default.disabled
		        )
		 FROM accounts acc
		 JOIN principals p ON p.id=acc.owner_principal_id AND p.tenant_id=acc.tenant_id
		 JOIN addresses addr ON addr.account_id=acc.id AND addr.tenant_id=acc.tenant_id AND NOT addr.is_alias
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 JOIN agent_mailbox_registrations registration
		   ON registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		  AND registration.owner_principal_id=acc.owner_principal_id
		  AND registration.space_id=$3
		 LEFT JOIN LATERAL (
		   SELECT id,bot_id,bot_profile,outbound_mode FROM agent_bindings
		   WHERE account_id=acc.id AND space_id=$3 AND status='active'
		   ORDER BY id DESC LIMIT 1
		 ) binding ON true
		 WHERE acc.tenant_id=$1 AND p.id=$2 AND NOT acc.disabled
		   AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		         AND gateway.owner_principal_id=acc.owner_principal_id
		         AND gateway.space_id=$3 AND NOT gateway.disabled
		   )
		 ORDER BY acc.created_at, acc.id`,
		t.info.ID, principalID, spaceID)
	if err != nil {
		return nil, fmt.Errorf("list agent mailboxes: %w", err)
	}
	defer rows.Close()
	var mailboxes []directory.AgentMailbox
	for rows.Next() {
		var mailbox directory.AgentMailbox
		if err := rows.Scan(&mailbox.ID, &mailbox.Address, &mailbox.BotID, &mailbox.BotProfile, &mailbox.ConnectState, &mailbox.OutboundMode, &mailbox.Deletable); err != nil {
			return nil, fmt.Errorf("scan agent mailbox: %w", err)
		}
		mailboxes = append(mailboxes, mailbox)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list agent mailboxes: %w", err)
	}
	return mailboxes, nil
}

func (t *tenantScope) DeleteAgentMailbox(ctx context.Context, principalID, accountID int64, spaceID string) error {
	spaceID = strings.TrimSpace(spaceID)
	if spaceID == "" {
		return directory.ErrAuthorizationSpaceMismatch
	}
	tx, err := t.s.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete Agent mailbox: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds

	var deletable bool
	err = tx.QueryRow(ctx,
		`SELECT NOT EXISTS (
		   SELECT 1 FROM gateway_identities gateway
		   WHERE gateway.default_account_id=acc.id
		     AND gateway.tenant_id=acc.tenant_id
		     AND gateway.owner_principal_id=acc.owner_principal_id
		     AND NOT gateway.disabled
		 )
		 FROM accounts acc
		 WHERE acc.id=$1 AND acc.tenant_id=$2 AND acc.owner_principal_id=$3
		   AND NOT acc.disabled
		   AND EXISTS (
		       SELECT 1 FROM agent_mailbox_registrations registration
		       WHERE registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		         AND registration.owner_principal_id=acc.owner_principal_id
		         AND registration.space_id=$4
		   )
		   AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway_space
		       WHERE gateway_space.default_account_id=acc.id
		         AND gateway_space.tenant_id=acc.tenant_id
		         AND gateway_space.owner_principal_id=acc.owner_principal_id
		         AND gateway_space.space_id=$4 AND NOT gateway_space.disabled
		   )
		 FOR UPDATE OF acc`,
		accountID, t.info.ID, principalID, spaceID).Scan(&deletable)
	if err == pgx.ErrNoRows {
		return directory.ErrMailboxNotFound
	}
	if err != nil {
		return fmt.Errorf("resolve Agent mailbox deletion: %w", err)
	}
	if !deletable {
		return directory.ErrAgentMailboxNotDeletable
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_binding_credentials SET revoked_at=now()
		 WHERE revoked_at IS NULL AND binding_id IN (
		   SELECT id FROM agent_bindings WHERE account_id=$1 AND status='active'
		 )`, accountID); err != nil {
		return fmt.Errorf("revoke Agent mailbox credentials: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE agent_bindings SET status='revoked',revoked_at=now()
		 WHERE account_id=$1 AND status='active'`, accountID); err != nil {
		return fmt.Errorf("revoke Agent mailbox binding: %w", err)
	}
	command, err := tx.Exec(ctx,
		`UPDATE accounts SET disabled=true WHERE id=$1 AND tenant_id=$2 AND owner_principal_id=$3 AND NOT disabled`,
		accountID, t.info.ID, principalID)
	if err != nil {
		return fmt.Errorf("disable Agent mailbox: %w", err)
	}
	if command.RowsAffected() != 1 {
		return directory.ErrMailboxNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete Agent mailbox: %w", err)
	}
	return nil
}

func (t *tenantScope) CreateAgentMailbox(ctx context.Context, principalID, sourceAccountID int64, spaceID, localpart, configuredDomain string, maxPerOwnerSpace int) (directory.AgentMailbox, error) {
	localpart = strings.ToLower(strings.TrimSpace(localpart))
	if !aliasLocalpartPattern.MatchString(localpart) || strings.Contains(localpart, "..") {
		return directory.AgentMailbox{}, directory.ErrInvalidLocalpart
	}
	spaceID = strings.TrimSpace(spaceID)
	if spaceID == "" {
		return directory.AgentMailbox{}, directory.ErrAuthorizationSpaceMismatch
	}
	if maxPerOwnerSpace <= 0 {
		maxPerOwnerSpace = 2
	}

	tx, err := t.s.Pool.Begin(ctx)
	if err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("begin create agent mailbox: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rolled back unless Commit succeeds

	// Registration is rare, so locking the owner row is a deliberately simple
	// cross-instance serialization point. It prevents two concurrent requests
	// from both observing one remaining slot and exceeding the configured limit.
	var lockedOwnerID int64
	if err := tx.QueryRow(ctx,
		`SELECT id FROM principals WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,
		principalID, t.info.ID).Scan(&lockedOwnerID); err == pgx.ErrNoRows {
		return directory.AgentMailbox{}, directory.ErrMailboxNotFound
	} else if err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("lock Agent mailbox owner: %w", err)
	}

	var domainID int64
	var domainName string
	err = tx.QueryRow(ctx,
		`SELECT addr.domain_id, dom.domain
		 FROM accounts acc
		 JOIN principals p ON p.id=acc.owner_principal_id AND p.tenant_id=acc.tenant_id
		 JOIN addresses addr ON addr.account_id=acc.id AND addr.tenant_id=acc.tenant_id AND NOT addr.is_alias
		 JOIN domains dom ON dom.id=addr.domain_id AND dom.tenant_id=addr.tenant_id
		 WHERE acc.tenant_id=$1 AND acc.id=$2 AND p.id=$3`,
		t.info.ID, sourceAccountID, principalID).Scan(&domainID, &domainName)
	if err == pgx.ErrNoRows {
		return directory.AgentMailbox{}, directory.ErrMailboxNotFound
	}
	if err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("resolve agent mailbox owner: %w", err)
	}
	if configuredDomain = strings.ToLower(strings.TrimSpace(configuredDomain)); configuredDomain != "" {
		err = tx.QueryRow(ctx,
			`SELECT id, domain
			 FROM domains
			 WHERE tenant_id=$1 AND domain=$2 AND NOT disabled`,
			t.info.ID, configuredDomain).Scan(&domainID, &domainName)
		if err == pgx.ErrNoRows {
			return directory.AgentMailbox{}, directory.ErrAgentMailboxDomainNotFound
		}
		if err != nil {
			return directory.AgentMailbox{}, fmt.Errorf("resolve configured Agent mailbox domain: %w", err)
		}
	}

	var registered int
	if err := tx.QueryRow(ctx,
		`SELECT count(*)
		 FROM accounts acc
		 JOIN agent_mailbox_registrations registration
		   ON registration.account_id=acc.id AND registration.tenant_id=acc.tenant_id
		  AND registration.owner_principal_id=acc.owner_principal_id
		  AND registration.space_id=$3
		 WHERE acc.tenant_id=$1 AND acc.owner_principal_id=$2 AND NOT acc.disabled
		   AND NOT EXISTS (
		       SELECT 1 FROM gateway_identities gateway
		       WHERE gateway.default_account_id=acc.id AND gateway.tenant_id=acc.tenant_id
		         AND gateway.owner_principal_id=acc.owner_principal_id
		         AND gateway.space_id=$3 AND NOT gateway.disabled
		   )`,
		t.info.ID, principalID, spaceID).Scan(&registered); err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("count Agent mailboxes in Space: %w", err)
	}
	if registered >= maxPerOwnerSpace {
		return directory.AgentMailbox{}, directory.ErrAgentMailboxLimit
	}

	var mailbox directory.AgentMailbox
	mailbox.Address = localpart + "@" + domainName
	var mailboxPrincipalID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO principals (tenant_id, login) VALUES ($1,$2) RETURNING id`,
		t.info.ID, mailbox.Address).Scan(&mailboxPrincipalID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return directory.AgentMailbox{}, directory.ErrAddressExists
		}
		return directory.AgentMailbox{}, fmt.Errorf("create agent mailbox principal: %w", err)
	}

	err = tx.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id, principal_id, owner_principal_id, name)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (tenant_id, name) DO NOTHING
		 RETURNING id`,
		t.info.ID, mailboxPrincipalID, principalID, "agent-mailbox:"+mailbox.Address).Scan(&mailbox.ID)
	if err == pgx.ErrNoRows {
		return directory.AgentMailbox{}, directory.ErrAddressExists
	}
	if err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("create agent mailbox account: %w", err)
	}

	var addressID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO addresses (tenant_id, domain_id, account_id, localpart, is_alias)
		 VALUES ($1,$2,$3,$4,false)
		 ON CONFLICT (domain_id, localpart) DO NOTHING
		 RETURNING id`,
		t.info.ID, domainID, mailbox.ID, localpart).Scan(&addressID)
	if err == pgx.ErrNoRows {
		return directory.AgentMailbox{}, directory.ErrAddressExists
	}
	if err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("create agent mailbox address: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO agent_mailbox_registrations
		 (tenant_id,account_id,owner_principal_id,space_id)
		 VALUES ($1,$2,$3,$4)`,
		t.info.ID, mailbox.ID, principalID, spaceID); err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("register Agent mailbox in Space: %w", err)
	}
	// Provision Inbox before publishing the new account. Reuse the normal mailbox
	// writer so the projection and changelog start in sync; no account-scoped
	// writer can race here because the account is still invisible until commit.
	account := t.s.openAccount(mailbox.ID, t.info.ID, "agent-mailbox:"+mailbox.Address)
	mailboxTx := &pgTx{ctx: ctx, tx: tx, acc: account, write: true}
	if _, err := mailboxTx.ensureMailbox("Inbox", true, store.SpecialUse{}); err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("create Agent mailbox Inbox: %w", err)
	}
	if err := mailboxTx.flush(); err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("initialize Agent mailbox changelog: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return directory.AgentMailbox{}, fmt.Errorf("commit agent mailbox: %w", err)
	}
	return mailbox, nil
}

func (t *tenantScope) Accounts(ctx context.Context) ([]store.Account, error) {
	rows, err := t.s.Pool.Query(ctx, `SELECT id, name FROM accounts WHERE tenant_id=$1`, t.info.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Account
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out = append(out, t.s.openAccount(id, t.info.ID, name))
	}
	return out, rows.Err()
}

func (t *tenantScope) Domain(ctx context.Context, dom dns.Domain) (directory.Domain, error) {
	var d directory.Domain
	err := t.s.Pool.QueryRow(ctx,
		`SELECT id, tenant_id, domain, disabled FROM domains WHERE tenant_id=$1 AND domain=$2`,
		t.info.ID, dom.Name()).Scan(&d.ID, &d.TenantID, new(string), &d.Disabled)
	if err == pgx.ErrNoRows {
		return directory.Domain{}, fmt.Errorf("no such domain")
	}
	if err != nil {
		return directory.Domain{}, err
	}
	d.Domain = dom
	return d, nil
}

func (t *tenantScope) Quota() directory.TenantQuota {
	var q directory.TenantQuota
	_ = t.s.Pool.QueryRow(context.Background(),
		`SELECT bytes_used, msg_count FROM quota_counters WHERE scope_type=0 AND scope_id=$1`,
		t.info.ID).Scan(&q.BytesUsed, &q.MsgCount)
	q.BytesLimit = t.info.QuotaBytes
	return q
}

// inboundTarget is the delivery-only capability for unauthenticated SMTP.
type inboundTarget struct {
	acc     *account
	tenant  directory.TenantInfo
	isAlias bool
}

func (it *inboundTarget) Deliver(ctx context.Context, m *store.Message, body store.BlobReader) ([]store.Change, error) {
	return it.acc.DeliverMailbox(ctx, "Inbox", m, body)
}
func (it *inboundTarget) DeliverTo(ctx context.Context, mailbox string, m *store.Message, body store.BlobReader) ([]store.Change, error) {
	return it.acc.DeliverMailbox(ctx, mailbox, m, body)
}
func (it *inboundTarget) AccountID() int64             { return it.acc.ID() }
func (it *inboundTarget) Tenant() directory.TenantInfo { return it.tenant }
func (it *inboundTarget) IsAlias() bool                { return it.isAlias }
func (it *inboundTarget) Rejected(reason string) error { return nil }
