// Package directory is the identity object graph and the root of tenant
// isolation. Isolation is structural, not a per-query discipline: the only way
// to obtain an Account handle is to navigate from a TenantScope you were granted
// (via authentication) or an InboundTarget (via inbound address resolution).
// There is deliberately no id-taking, tenant-crossing accessor anywhere — a
// handler holding tenant A's scope has no reference through which to name tenant
// B's objects. This replaces a flat, global Account(name) /
// LookupAddress, where isolation was "pass the right name".
package directory

import (
	"context"
	"errors"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

var (
	ErrAddressNotFound            = errors.New("directory: address not found")
	ErrAddressExists              = errors.New("directory: address already exists")
	ErrMailboxNotFound            = errors.New("directory: agent mailbox not found")
	ErrAgentBindingNotFound       = errors.New("directory: active agent binding not found")
	ErrPrimaryAddress             = errors.New("directory: primary address cannot be deleted")
	ErrInvalidLocalpart           = errors.New("directory: invalid address localpart")
	ErrAgentMailboxDomainNotFound = errors.New("directory: Agent mailbox domain not found")
	ErrAgentMailboxLimit          = errors.New("directory: Agent mailbox limit reached")
	ErrAgentMailboxNotDeletable   = errors.New("directory: Agent mailbox cannot be deleted")
	ErrAuthorizationNotFound      = errors.New("directory: agent authorization not found")
	ErrAuthorizationSpaceMismatch = errors.New("directory: agent authorization space mismatch")
	ErrAuthorizationPending       = errors.New("directory: agent authorization pending")
	ErrAuthorizationExpired       = errors.New("directory: agent authorization expired")
	ErrAuthorizationUsed          = errors.New("directory: agent authorization already used")
	ErrAuthorizationDenied        = errors.New("directory: agent authorization denied")
	ErrInvalidCodeVerifier        = errors.New("directory: invalid authorization code verifier")
	ErrMailRuleNotFound           = errors.New("directory: mail rule not found")
	ErrMailRuleInvalid            = errors.New("directory: invalid mail rule")
	ErrMailRuleLimit              = errors.New("directory: enabled mail rule limit reached")
)

// TenantInfo identifies a tenant. Quota/limits hang off it.
type TenantInfo struct {
	ID         int64
	Name       string
	QuotaBytes int64
}

// Credential is an authentication secret (SCRAM exchange, password, TLS pubkey).
// Concrete types live in the auth path; Directory only verifies.
type Credential any

// PasswordCredential is a plaintext password presented for verification against
// the principal's stored argon2id hash. Network entry points must pass this;
// a nil Credential is resolve-only and reserved for trusted internal callers.
type PasswordCredential string

// Principal is an authenticated identity within a tenant.
type Principal struct {
	ID       int64
	TenantID int64
	Login    string
}

// Directory is the entry point. It yields only tenant-scoped capabilities.
type Directory interface {
	// AuthenticatePrincipal verifies a login and returns a scope bound to
	// exactly one tenant.
	AuthenticatePrincipal(ctx context.Context, login string, cred Credential) (TenantScope, Principal, error)

	// AuthenticateAPIKey verifies a bearer API key (form omk_<prefix>_<secret>)
	// and returns the tenant scope, principal, and the account id the key acts as.
	// It is the account-scoped equivalent of a login, used by the JMAP/WebAPI
	// HTTP surfaces for agent-facing Bearer auth.
	AuthenticateAPIKey(ctx context.Context, token string) (TenantScope, Principal, int64, error)

	// ResolveInbound is the ONLY unauthenticated resolver. Inbound SMTP arrives
	// at a domain with no principal; this returns a delivery-only handle bound
	// to a single account. It cannot be widened to read or list the mailbox.
	ResolveInbound(ctx context.Context, addr smtp.Path) (InboundTarget, error)
}

// SCRAMVerifier is a stored SCRAM-SHA-256 salted-password verifier, returned by
// a SCRAMAuthenticator so the protocol layer can run the SASL exchange without
// the plaintext password ever being present.
type SCRAMVerifier struct {
	Salt           []byte
	SaltedPassword []byte
	Iterations     int
}

// SCRAMAuthenticator is optionally implemented by a Directory to support the
// SASL SCRAM-SHA-256 mechanism. The protocol server looks up the verifier,
// drives the challenge/response exchange itself (proving the client knows the
// password without transmitting it), then calls ScopeForLogin to obtain the
// tenant-bound capability. ScopeForLogin performs no credential check — it is
// only called after the SCRAM proof has been verified.
type SCRAMAuthenticator interface {
	LookupSCRAM(ctx context.Context, login string) (SCRAMVerifier, error)
	ScopeForLogin(ctx context.Context, login string) (TenantScope, Principal, error)
}

// TenantScope is a capability scoped to one tenant. Every accessor returns only
// this tenant's objects; there is no method to reach another tenant.
type TenantScope interface {
	Tenant() TenantInfo
	Account(ctx context.Context, name string) (store.Account, error)
	// AccountForAddress resolves one of this tenant's email addresses to the
	// owning account (address localpart may differ from account name). Used by
	// submission auth, where the login is an email address.
	AccountForAddress(ctx context.Context, addr smtp.Path) (store.Account, error)
	// AccountForID resolves an account by id WITHIN this tenant. An id belonging to
	// another tenant matches nothing (structural isolation). Used by API-key auth
	// to open the exact account the key was bound to at issuance, rather than
	// re-deriving it from the login address (which can be repointed).
	AccountForID(ctx context.Context, id int64) (store.Account, error)
	AccountAddresses(ctx context.Context, accountID int64) ([]MailAddress, error)
	CreateAccountAlias(ctx context.Context, accountID int64, localpart string) (MailAddress, error)
	DeleteAccountAlias(ctx context.Context, accountID, addressID int64) error
	AgentMailboxes(ctx context.Context, principalID int64, spaceID string) ([]AgentMailbox, error)
	CreateAgentMailbox(ctx context.Context, principalID, sourceAccountID int64, spaceID, localpart, configuredDomain string, maxPerOwnerSpace int) (AgentMailbox, error)
	DeleteAgentMailbox(ctx context.Context, principalID, accountID int64, spaceID string) error
	Accounts(ctx context.Context) ([]store.Account, error)
	Domain(ctx context.Context, d dns.Domain) (Domain, error)
	Quota() TenantQuota
}

// MailAddress is an address routed to one account within a tenant.
type MailAddress struct {
	ID      int64
	Address string
	Primary bool
}

// AgentMailbox is one independently stored mailbox owned by an authenticated
// principal. Unlike MailAddress aliases, each AgentMailbox has its own account,
// message log, folders, quota counters, and credentials.
type AgentMailbox struct {
	ID           int64
	Address      string
	BotID        string
	BotProfile   string
	ConnectState string
	OutboundMode AgentOutboundMode
	Deletable    bool
}

// AgentOutboundMode is the owner-approved external-side-effect policy stored
// on the current mailbox binding. It is deliberately broader than the legacy
// auto_reply_enabled flag: automatic send covers owner-directed new messages
// and ordinary replies, while all hard safety checks remain authoritative.
type AgentOutboundMode string

const (
	AgentOutboundModeManualConfirmation AgentOutboundMode = "manual_confirmation"
	AgentOutboundModeAutomaticSend      AgentOutboundMode = "automatic_send"
)

func (m AgentOutboundMode) Valid() bool {
	return m == AgentOutboundModeManualConfirmation || m == AgentOutboundModeAutomaticSend
}

// AgentMailRuleScope is an optional owner-management capability implemented by
// tenant scopes that persist post-storage product rules. It is separate from
// TenantScope so protocol-only directory implementations do not have to expose
// rule storage.
type AgentMailRuleScope interface {
	AgentMailRules(ctx context.Context, ownerPrincipalID, accountID int64) ([]MailRule, error)
	CreateAgentMailRule(ctx context.Context, ownerPrincipalID, accountID int64, input MailRuleInput) (MailRule, error)
	UpdateAgentMailRule(ctx context.Context, ownerPrincipalID, accountID, ruleID int64, patch MailRulePatch) (MailRule, error)
	DeleteAgentMailRule(ctx context.Context, ownerPrincipalID, accountID, ruleID int64) error
	AgentMailRuleExecutions(ctx context.Context, ownerPrincipalID, accountID int64, limit int) ([]MailRuleExecution, error)
}

// MailRule is one bounded post-storage sender/subject forwarding rule.
type MailRule struct {
	ID             int64
	AccountID      int64
	Name           string
	Enabled        bool
	Priority       int
	MatchFrom      string
	MatchSubject   string
	ForwardTargets []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type MailRuleInput struct {
	Name           string
	Enabled        bool
	Priority       int
	MatchFrom      string
	MatchSubject   string
	ForwardTargets []string
}

type MailRulePatch struct {
	Name           *string
	Enabled        *bool
	Priority       *int
	MatchFrom      *string
	MatchSubject   *string
	ForwardTargets *[]string
}

type MailRuleExecution struct {
	ID            int64
	RuleID        int64
	SourceEmailID int64
	Status        string
	TargetResults []byte
	HopCount      int
	ErrorCode     string
	CreatedAt     time.Time
	CompletedAt   *time.Time
}

// AgentAuthorizationDirectory is the optional Agent Mail device-authorization
// capability implemented by persistent directories. Keeping it separate from
// Directory avoids forcing protocol-only test doubles to implement onboarding.
type AgentAuthorizationDirectory interface {
	CreateAgentAuthorization(ctx context.Context, input AgentAuthorizationInput) (AgentDeviceAuthorization, error)
	AgentAuthorization(ctx context.Context, ownerPrincipalID int64, spaceID, userCode string) (AgentAuthorization, error)
	ApproveAgentAuthorization(ctx context.Context, ownerPrincipalID int64, spaceID, userCode string, accountID int64, outboundMode AgentOutboundMode) error
	ExchangeAgentAuthorization(ctx context.Context, deviceCode, codeVerifier string) (AgentAuthorizationCredential, error)
	RevokeAgentBinding(ctx context.Context, ownerPrincipalID, accountID int64) error
	SetAgentOutboundMode(ctx context.Context, ownerPrincipalID, accountID int64, mode AgentOutboundMode) error
	AuthenticateAgentCredential(ctx context.Context, token string) (TenantScope, Principal, int64, int64, error)
	AgentAutomationAllowed(ctx context.Context, credentialID int64, operation string) (bool, error)
}

// GatewayIdentityDirectory resolves a short-lived assertion from a trusted
// OCTO gateway to one provisioned human mailbox owner. The selected account is
// optional; when present it must still be owned by that exact principal.
type GatewayIdentityDirectory interface {
	AuthenticateGatewayIdentity(ctx context.Context, issuer, subject, spaceID string, selectedAccountID int64) (TenantScope, Principal, int64, error)
}

// GatewayAssertionReplayDirectory consumes one signed gateway assertion nonce.
// Implementations must reject a repeated issuer+nonce pair across instances.
type GatewayAssertionReplayDirectory interface {
	ConsumeGatewayAssertionNonce(ctx context.Context, issuer, nonce string, expiresAt, now time.Time) error
}

type AgentAuthorizationInput struct {
	BotID         string
	BotProfile    string
	ClientName    string
	SpaceID       string
	CodeChallenge string
}

type AgentDeviceAuthorization struct {
	DeviceCode string
	UserCode   string
	ExpiresIn  int
	Interval   int
}

type AgentAuthorization struct {
	UserCode            string
	BotID               string
	BotProfile          string
	ClientName          string
	SpaceID             string
	Status              string
	RequestedAt         string
	ExpiresAt           string
	PollIntervalSeconds int
	OutboundMode        AgentOutboundMode
}

type AgentAuthorizationCredential struct {
	AccessToken  string
	Address      string
	BotID        string
	BotProfile   string
	OutboundMode AgentOutboundMode
}

// Domain is a tenant-owned domain.
type Domain struct {
	ID       int64
	TenantID int64
	Domain   dns.Domain
	Disabled bool
}

// TenantQuota reports per-tenant usage/limits (a projection of the log).
type TenantQuota struct {
	BytesUsed  int64
	BytesLimit int64
	MsgCount   int64
}

// InboundTarget is the minimum capability for unauthenticated delivery: append
// to one account, nothing else. It carries the tenant id for reputation
// attribution but exposes no way to read the mailbox or reach siblings.
type InboundTarget interface {
	Deliver(ctx context.Context, m *store.Message, body store.BlobReader) ([]store.Change, error)
	// DeliverTo appends to a named mailbox (e.g. "Junk"), creating it if needed.
	// Used by the receiver to route spam-classified mail to the Junk mailbox.
	DeliverTo(ctx context.Context, mailbox string, m *store.Message, body store.BlobReader) ([]store.Change, error)
	// AccountID identifies the destination account, for per-account junk
	// classification/training (not a capability to reach other accounts).
	AccountID() int64
	Tenant() TenantInfo
	IsAlias() bool
	Rejected(reason string) error
}
