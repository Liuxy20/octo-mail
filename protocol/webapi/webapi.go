// Package webapi is octo-mail's RESTful HTTP/JSON API for programmatic mail. It
// is a per-account surface — authenticated with an account API key
// (Authorization: Bearer omk_...) or HTTP Basic — for sending mail and managing
// messages, threads, drafts, mailboxes, and the suppression list, without
// speaking SMTP/IMAP/JMAP. It sits on the same kernel primitives: Send enqueues
// to the shared outbound queue; message ops go through the account's change-log.
//
// The API is resource-oriented under /webapi/v0: real HTTP verbs, correct status
// codes, camelCase JSON, and a small {"error":{"code","message"}} body on
// failure. Provisioning (tenants/accounts/domains) is deliberately NOT here — it
// lives on the admin surface; an account key can only reach its own mailbox.
package webapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/autoreplychain"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/deliverability"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/outboundpolicy"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/smtp"
)

// Server serves the REST webapi. Submission enqueues outbound mail; Suppressions
// manages the per-account suppression list.
type Server struct {
	Dir          directory.Directory
	Submission   messageSubmitter
	Suppressions *deliverability.Suppressions
	// Log, if set, records the full internal error behind a 500; the client only
	// ever gets a generic message, so raw DB/driver text can't leak. Optional.
	Log *slog.Logger
	// LoginLimiter, if set, throttles failed authentication attempts per client IP
	// (brute-force / credential-stuffing + enumeration defense). Optional.
	LoginLimiter *ratelimit.Limiter
	// DeviceFlowLimiter, if set, throttles every public device creation and token
	// polling request with a coarse per-source budget. Behind a trusted reverse
	// proxy this intentionally becomes a deployment-wide circuit breaker.
	DeviceFlowLimiter *ratelimit.Limiter
	// DeviceCreateLimiter bounds device-flow creation per source address without
	// consuming the budget used by normal token polling.
	DeviceCreateLimiter *ratelimit.Limiter
	// DeviceTokenLimiter bounds token polling per opaque device code. This keeps
	// concurrent authorizations independent even when a reverse proxy is the
	// RemoteAddr for every request.
	DeviceTokenLimiter *ratelimit.Limiter
	// AuthorizationURL is the octo-web page where a human owner approves a
	// device request. It may be absolute in deployments or a gateway-relative
	// path when octo-mail and octo-web share an origin.
	AuthorizationURL string
	// GatewaySecret verifies short-lived identity assertions minted by the
	// authenticated OCTO gateway. Empty disables this authentication path.
	GatewaySecret []byte
	// OutboundPolicy evaluates Agent-originated outbound content after the
	// owner/automation authorization gate and before any Sent copy or queue
	// side effect. Nil preserves the historical allow-all behavior.
	OutboundPolicy outboundpolicy.Evaluator
	// AutoReplyChain authenticates and bounds owner-approved Agent automatic
	// replies. Nil is the explicit rollback/disabled behavior.
	AutoReplyChain *autoreplychain.Chain
	// RuleMetadata verifies server-generated forwarding attribution before it is
	// exposed to clients. Nil fails closed and treats all such headers as external.
	RuleMetadata *rulemetadata.Authenticator
	// MaxAgentMailboxesPerOwnerSpace is the total per-owner, per-Space Agent
	// mailbox limit, including the gateway default Agent mailbox. The directory
	// enforces it transactionally when another mailbox is registered. Zero keeps
	// the safe product default of two for embedders/tests that omit the field.
	MaxAgentMailboxesPerOwnerSpace int
	// AgentMailboxDomain, when configured, is the tenant-owned address domain
	// used for newly registered Agent mailboxes and advertised to the owner UI.
	// Empty preserves the legacy behavior of inheriting the source account domain.
	AgentMailboxDomain string
	// MaxMessageSize bounds WebAPI request bodies and MIME message parsing.
	// Zero preserves the historical 64 MiB limit for direct embedders/tests.
	MaxMessageSize int64
}

const (
	defaultMaxAgentMailboxesPerOwnerSpace = 2
	defaultMaxMessageSize                 = 64 << 20
	maxDeviceAuthorizationBodySize        = 4 << 10
)

func (s *Server) maxAgentMailboxesPerOwnerSpace() int {
	if s.MaxAgentMailboxesPerOwnerSpace > 0 {
		return s.MaxAgentMailboxesPerOwnerSpace
	}
	return defaultMaxAgentMailboxesPerOwnerSpace
}

func (s *Server) maxMessageSize() int64 {
	if s.MaxMessageSize > 0 {
		return s.MaxMessageSize
	}
	return defaultMaxMessageSize
}

// Handler mounts the REST routes using Go 1.22 method+path patterns. Business
// routes under /webapi/v0 authenticate via s.auth; the internal provisioning
// route verifies its own request-bound gateway assertion.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Trusted OCTO gateway provisioning. This path is not reachable through the
	// browser gateway; it authenticates its own exact request-bound assertion.
	mux.HandleFunc("POST /internal/v0/gateway-identities/ensure", s.ensureGatewayIdentity)
	// Messages.
	mux.HandleFunc("GET /webapi/v0/messages", s.h(s.listMessages))
	mux.HandleFunc("POST /webapi/v0/messages", s.hAgentConfirmed("mail.message.send", s.sendMessage))
	mux.HandleFunc("GET /webapi/v0/messages/{id}", s.h(s.getMessage))
	mux.HandleFunc("PATCH /webapi/v0/messages/{id}", s.h(s.patchMessage))
	mux.HandleFunc("DELETE /webapi/v0/messages/{id}", s.hAgentConfirmed("mail.message.delete", s.deleteMessage))
	mux.HandleFunc("GET /webapi/v0/messages/{id}/raw", s.hRaw(s.rawMessage))
	mux.HandleFunc("GET /webapi/v0/messages/{id}/attachments/{partId}", s.downloadAttachment)
	mux.HandleFunc("GET /webapi/v0/messages/{id}/delivery", s.h(s.getMessageDelivery))
	mux.HandleFunc("GET /webapi/v0/messages/{id}/auto-reply-context", s.h(s.getAutoReplyContext))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/reply-draft", s.h(s.createAgentReplyDraft))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/reply", s.hAgentConfirmed("mail.message.reply", s.replyMessage))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/reply-all", s.hAgentConfirmed("mail.message.reply_all", s.replyAllMessage))
	mux.HandleFunc("POST /webapi/v0/messages/{id}/forward", s.hAgentConfirmed("mail.message.forward", s.forwardMessage))
	// Threads.
	mux.HandleFunc("GET /webapi/v0/threads/{id}", s.h(s.getThread))
	// Drafts.
	mux.HandleFunc("GET /webapi/v0/drafts", s.h(s.listDrafts))
	mux.HandleFunc("POST /webapi/v0/agent-send-intents", s.h(s.createAgentSendIntent))
	mux.HandleFunc("POST /webapi/v0/agent-drafts", s.h(s.createAgentDraft))
	mux.HandleFunc("POST /webapi/v0/drafts", s.h(s.createDraft))
	mux.HandleFunc("PATCH /webapi/v0/drafts/{id}", s.h(s.updateDraft))
	mux.HandleFunc("POST /webapi/v0/drafts/{id}/send", s.hAgentConfirmed("mail.draft.send", s.sendDraft))
	mux.HandleFunc("DELETE /webapi/v0/drafts/{id}", s.hAgentConfirmed("mail.draft.delete", s.deleteDraft))
	// Mailboxes.
	mux.HandleFunc("GET /webapi/v0/mailboxes", s.h(s.listMailboxes))
	mux.HandleFunc("GET /webapi/v0/identity", s.h(s.getIdentity))
	// Account addresses.
	mux.HandleFunc("GET /webapi/v0/addresses", s.h(s.listAddresses))
	mux.HandleFunc("POST /webapi/v0/addresses", s.h(s.createAddress))
	mux.HandleFunc("DELETE /webapi/v0/addresses/{id}", s.h(s.deleteAddress))
	// Independent Agent mailboxes owned by the authenticated principal.
	mux.HandleFunc("GET /webapi/v0/agent-mailboxes", s.h(s.listAgentMailboxes))
	mux.HandleFunc("POST /webapi/v0/agent-mailboxes", s.h(s.createAgentMailbox))
	mux.HandleFunc("DELETE /webapi/v0/agent-mailboxes/{id}", s.h(s.deleteAgentMailbox))
	mux.HandleFunc("DELETE /webapi/v0/agent-mailboxes/{id}/binding", s.h(s.revokeAgentMailboxBinding))
	mux.HandleFunc("PATCH /webapi/v0/agent-mailboxes/{id}/automation", s.h(s.updateAgentMailboxAutomation))
	mux.HandleFunc("GET /webapi/v0/agent-mailboxes/{mailboxId}/rules", s.h(s.listAgentMailRules))
	mux.HandleFunc("POST /webapi/v0/agent-mailboxes/{mailboxId}/rules", s.h(s.createAgentMailRule))
	mux.HandleFunc("PATCH /webapi/v0/agent-mailboxes/{mailboxId}/rules/{ruleId}", s.h(s.updateAgentMailRule))
	mux.HandleFunc("DELETE /webapi/v0/agent-mailboxes/{mailboxId}/rules/{ruleId}", s.h(s.deleteAgentMailRule))
	mux.HandleFunc("GET /webapi/v0/agent-mailboxes/{mailboxId}/rule-executions", s.h(s.listAgentMailRuleExecutions))
	// Agent device authorization. Device creation and token exchange are public
	// OAuth-style endpoints; request inspection/approval requires the owner.
	mux.HandleFunc("POST /webapi/v0/agent-auth/device", s.deviceFlowLimited(s.deviceCreateLimited(s.deviceBodyLimited(s.createAgentDeviceAuthorization))))
	mux.HandleFunc("POST /webapi/v0/agent-auth/token", s.deviceFlowLimited(s.deviceBodyLimited(s.exchangeAgentAuthorization)))
	mux.HandleFunc("GET /webapi/v0/agent-auth/requests/{code}", s.h(s.getAgentAuthorization))
	mux.HandleFunc("POST /webapi/v0/agent-auth/requests/{code}/approve", s.h(s.approveAgentAuthorization))
	// Suppressions.
	mux.HandleFunc("GET /webapi/v0/suppressions", s.h(s.listSuppressions))
	mux.HandleFunc("GET /webapi/v0/suppressions/{address}", s.h(s.getSuppression))
	mux.HandleFunc("PUT /webapi/v0/suppressions/{address}", s.h(s.putSuppression))
	mux.HandleFunc("DELETE /webapi/v0/suppressions/{address}", s.h(s.deleteSuppression))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.maxMessageSize())
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) deviceFlowLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.DeviceFlowLimiter != nil && ip != nil {
			if !s.DeviceFlowLimiter.Add(ip, time.Now(), 1) {
				s.writeErr(w, r, errStatus(http.StatusTooManyRequests, "slow_down", "device authorization requests are too frequent"))
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) deviceCreateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.DeviceCreateLimiter != nil && ip != nil && !s.DeviceCreateLimiter.Add(ip, time.Now(), 1) {
			s.writeErr(w, r, errStatus(http.StatusTooManyRequests, "slow_down", "device authorization requests are too frequent"))
			return
		}
		next(w, r)
	}
}

func (s *Server) deviceBodyLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxDeviceAuthorizationBodySize)
		next(w, r)
	}
}

func deviceCodeLimitKey(deviceCode string) net.IP {
	digest := sha256.Sum256([]byte(strings.TrimSpace(deviceCode)))
	return net.IPv4(digest[0], digest[1], digest[2], digest[3])
}

func (s *Server) allowDeviceTokenPoll(deviceCode string) bool {
	return s.DeviceTokenLimiter == nil || s.DeviceTokenLimiter.Add(deviceCodeLimitKey(deviceCode), time.Now(), 1)
}

// authCtx carries the authenticated account for a request.
type authCtx struct {
	acc                 store.Account
	scope               directory.TenantScope
	principal           directory.Principal
	login               string
	spaceID             string
	agentCredentialID   int64
	humanAuthenticated  bool
	ownerConfirmedDraft bool
}

// auth authenticates the request, throttling by client IP: it refuses once the
// per-IP failed-attempt window is exceeded (before any credential work), and
// counts each failure — so brute-force / credential-stuffing and login/API-key
// enumeration are bounded.
func (s *Server) auth(r *http.Request) (authCtx, error) {
	ip := clientIP(r)
	if s.LoginLimiter != nil && ip != nil && !s.LoginLimiter.CanAdd(ip, time.Now(), 1) {
		return authCtx{}, errStatus(http.StatusTooManyRequests, "rate_limited", "too many authentication attempts")
	}
	a, err := s.authenticate(r)
	if err != nil && s.LoginLimiter != nil && ip != nil {
		s.LoginLimiter.Add(ip, time.Now(), 1) // count only failures
	}
	return a, err
}

// clientIP extracts the client IP from the request's RemoteAddr. It intentionally
// does NOT trust X-Forwarded-For (that would let a client spoof its rate-limit
// key); a fronting proxy must set RemoteAddr or terminate limiting itself.
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (s *Server) authenticate(r *http.Request) (authCtx, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omg_") {
		if len(s.GatewaySecret) < 32 {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		body, err := readAndRestoreAuthBody(r, s.maxMessageSize())
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		selectedMailbox := strings.TrimSpace(r.Header.Get("X-Octo-Mailbox-ID"))
		verificationTime := time.Now().UTC()
		claims, err := gatewayassert.VerifyForMailbox(s.GatewaySecret, strings.TrimPrefix(h, "Bearer "), selectedMailbox, r.Method, r.URL.RequestURI(), body, verificationTime)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		replayDir, ok := s.Dir.(directory.GatewayAssertionReplayDirectory)
		if !ok || replayDir.ConsumeGatewayAssertionNonce(r.Context(), claims.Issuer, claims.Nonce, time.Unix(claims.ExpiresAt, 0), verificationTime) != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		gatewayDir, ok := s.Dir.(directory.GatewayIdentityDirectory)
		if !ok {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		selectedAccountID := int64(0)
		if raw := selectedMailbox; raw != "" {
			selectedAccountID, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || selectedAccountID <= 0 {
				return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
			}
		}
		scope, principal, accountID, err := gatewayDir.AuthenticateGatewayIdentity(r.Context(), claims.Issuer, claims.Subject, claims.SpaceID, selectedAccountID)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		acc, err := scope.AccountForID(r.Context(), accountID)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		login, err := primaryAccountAddress(r.Context(), scope, accountID)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		return authCtx{acc: acc, scope: scope, principal: principal, login: login, spaceID: claims.SpaceID, humanAuthenticated: true}, nil
	}
	// API key first: Authorization: Bearer omk_<prefix>_<secret>.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omk_") {
		token := strings.TrimPrefix(h, "Bearer ")
		scope, princ, accountID, err := s.Dir.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		// Open the account the key was BOUND to (accountID), not one re-derived from
		// the login address — a repointed address must not change which account the
		// key acts as.
		acc, err := scope.AccountForID(r.Context(), accountID)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "no account for key")
		}
		return authCtx{acc: acc, scope: scope, principal: princ, login: princ.Login}, nil
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omb_") {
		token := strings.TrimPrefix(h, "Bearer ")
		agentDir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
		if !ok {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		scope, princ, accountID, credentialID, err := agentDir.AuthenticateAgentCredential(r.Context(), token)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
		}
		acc, err := scope.AccountForID(r.Context(), accountID)
		if err != nil {
			return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "no account for credential")
		}
		return authCtx{
			acc: acc, scope: scope, principal: princ, login: princ.Login,
			agentCredentialID: credentialID,
		}, nil
	}

	login, password, ok := r.BasicAuth()
	if !ok {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "missing credentials")
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "bad login address")
	}
	scope, principal, err := s.Dir.AuthenticatePrincipal(r.Context(), login, directory.PasswordCredential(password))
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "authentication failed")
	}
	acc, err := scope.AccountForAddress(r.Context(), addr.Path())
	if err != nil {
		return authCtx{}, errStatus(http.StatusUnauthorized, "unauthorized", "no account for login")
	}
	return authCtx{acc: acc, scope: scope, principal: principal, login: login, humanAuthenticated: true}, nil
}

func primaryAccountAddress(ctx context.Context, scope directory.TenantScope, accountID int64) (string, error) {
	addresses, err := scope.AccountAddresses(ctx, accountID)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if address.Primary && strings.TrimSpace(address.Address) != "" {
			return address.Address, nil
		}
	}
	return "", fmt.Errorf("account %d has no primary address", accountID)
}

func readAndRestoreAuthBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, fmt.Errorf("request body unavailable")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// handler is a REST handler that returns (status, body) or an error. A nil body
// with status 204 writes no content.
type handler func(ctx context.Context, a authCtx, r *http.Request) (status int, body any, err error)

// h wraps a handler with auth + JSON error mapping.
func (s *Server) h(fn handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.auth(r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		status, body, err := fn(r.Context(), a, r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if status == http.StatusNoContent || body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	}
}

// hRaw wraps a handler that streams raw bytes (message/rfc822).
func (s *Server) hRaw(fn func(ctx context.Context, a authCtx, r *http.Request) (store.BlobReader, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.auth(r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		rc, err := fn(r.Context(), a, r)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "message/rfc822")
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 32*1024)
		for {
			n, e := rc.Read(buf)
			if n > 0 {
				if _, we := w.Write(buf[:n]); we != nil {
					return
				}
			}
			if e != nil {
				return
			}
		}
	}
}

// --- shared helpers ---

// decode reads and JSON-decodes the request body (capped) into v.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errStatus(http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		}
		return errStatus(http.StatusBadRequest, "invalid_body", "invalid JSON body: "+err.Error())
	}
	return nil
}

// decodeStrict is used by security-sensitive intent endpoints whose accepted
// field set is part of the authorization scope. Unknown fields must not be
// silently ignored and later interpreted differently by another component.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errStatus(http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		}
		return errStatus(http.StatusBadRequest, "invalid_body", "invalid JSON body: "+err.Error())
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errStatus(http.StatusBadRequest, "invalid_body", "request body must contain exactly one JSON value")
	}
	return nil
}

// parseEmailID decodes an "E<n>" message id to its effective email id.
func parseEmailID(id string) (int64, bool) {
	if len(id) < 2 || id[0] != 'E' {
		return 0, false
	}
	n, err := strconv.ParseInt(id[1:], 10, 64)
	return n, err == nil
}

func emailID(m store.Message) string {
	return "E" + strconv.FormatInt(m.EffectiveEmailID(), 10)
}

// loadGroup loads all live rows of a message (across mailboxes) by its "E<n>" id.
func loadGroup(tx store.Tx, acc store.Account, id string) ([]store.Message, error) {
	gid, ok := parseEmailID(id)
	if !ok {
		return nil, errStatus(http.StatusBadRequest, "invalid_id", "invalid message id")
	}
	msgs, err := acc.MessagesByEmailID(tx, gid)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, errStatus(http.StatusNotFound, "not_found", "no such message")
	}
	return msgs, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusError carries an HTTP status + machine code + client-safe message. An
// optional cause holds the underlying internal error for server-side logging
// only — it is NEVER sent to the client. Build client-facing errors with
// errStatus (msg is shown verbatim) and internal failures with internalErr
// (msg is generic, the real error goes only to the log).
type statusError struct {
	status int
	code   string
	msg    string
	cause  error
	policy any
}

func (e *statusError) Error() string { return e.msg }
func (e *statusError) Unwrap() error { return e.cause }

func errStatus(status int, code, msg string) *statusError {
	return &statusError{status: status, code: code, msg: msg}
}

// internalErr wraps an internal failure as a 500 whose client-facing message is
// generic; cause is retained for server-side logging in writeErr and never
// reaches the client, so DB constraint names, SQL, and filesystem paths don't
// leak. code stays meaningful (e.g. "submit_failed") for client dispatch.
func internalErr(code string, cause error) *statusError {
	return &statusError{status: http.StatusInternalServerError, code: code, msg: "internal error", cause: cause}
}

// writeErr renders an error: a *statusError uses its status and crafted message
// (logging its cause server-side, if any); anything else is logged server-side
// (if Log is set) and returned as a generic 500 so raw internal error text (DB
// constraint names, SQL, paths) never reaches the client.
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	se, ok := err.(*statusError)
	if !ok {
		se = internalErr("internal", err)
	}
	if se.cause != nil && s.Log != nil {
		s.Log.WarnContext(r.Context(), "webapi internal error", "method", r.Method, "path", r.URL.Path, "code", se.code, "err", se.cause)
	}
	body := map[string]any{
		"error": map[string]string{"code": se.code, "message": se.msg},
	}
	if se.policy != nil {
		body["policy"] = se.policy
	}
	writeJSON(w, se.status, body)
}

// senderDomain returns the account login's domain, for Message-ID generation.
func (a authCtx) senderDomain() string {
	if i := strings.LastIndex(a.login, "@"); i >= 0 {
		return a.login[i+1:]
	}
	return "localhost"
}
