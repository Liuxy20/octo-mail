// Package jmapd is a compact, real JMAP server (RFC 8620 core + RFC 8621 mail
// subset) bound to the octo-mail kernel. Its purpose is to demonstrate the
// architecture's central symmetry: IMAP and JMAP are two projections of the same
// per-account change-log. Concretely, the JMAP "state" string IS the account's
// changelog offset, and Email/changes(sinceState=n) is the same replay
// (modseq > n) that IMAP serves as CONDSTORE CHANGEDSINCE n — two renderers over
// one log.
//
// It speaks HTTP/JSON and is tested with the standard net/http client.
package jmapd

import (
	"context"
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
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/ratelimit"
	"github.com/mjl-/mox/smtp"
)

// Server serves JMAP over HTTP, resolving the authenticated principal through
// the directory (structural tenant isolation).
type Server struct {
	Dir     directory.Directory
	BaseURL string // e.g. "http://localhost:8080"
	// MaxSizeUpload bounds one JMAP upload and is advertised in the JMAP
	// Session. Zero preserves the historical 50,000,000-byte default for
	// embedders and tests that construct Server directly.
	MaxSizeUpload int64
	// Submission, if set, enables EmailSubmission/set: it enqueues outbound mail
	// to the shared queue (the JMAP counterpart of SMTP submission on 587).
	Submission *submit.Submitter
	// Blob, if set, enables the upload endpoint and Email/set create: uploaded
	// message bytes are stored here (content-addressed, per tenant) and referenced
	// by blobId.
	Blob blob.Store
	// Log, if set, records the full internal error behind a serverFail; the client
	// only ever gets a generic description, so raw DB/driver text can't leak.
	Log *slog.Logger
	// LoginLimiter, if set, throttles failed authentication attempts per client IP
	// (brute-force + login/API-key enumeration defense). Optional.
	LoginLimiter *ratelimit.Limiter
}

// serverFail builds a JMAP method-level error, logging the underlying error
// server-side (if Log is set) and returning a GENERIC description — raw internal
// error text (DB constraint names, SQL, filesystem paths) must never reach a
// client. Use for any error derived from internal failures.
func (s *Server) serverFail(err error) (string, any) {
	if s.Log != nil && err != nil {
		s.Log.Warn("jmap serverFail", "err", err)
	}
	return "error", map[string]any{"type": "serverFail", "description": "internal error"}
}

// serverFailObj is serverFail's value-only form, for per-object error maps (e.g.
// Email/set notCreated) where only the error object is needed, not the (name,
// args) pair.
func (s *Server) serverFailObj(err error) map[string]any {
	if s.Log != nil && err != nil {
		s.Log.Warn("jmap serverFail", "err", err)
	}
	return map[string]any{"type": "serverFail", "description": "internal error"}
}

// JMAP request limits (RFC 8620 §2.1). These are both advertised in the session
// capabilities AND enforced on the request path, so they never drift: an
// oversized upload or an over-long method batch is rejected instead of buffered.
const (
	// defaultMaxSizeUpload bounds a single /jmap/upload body (bytes) when the
	// composition root does not provide an explicit deployment limit.
	defaultMaxSizeUpload = 50_000_000
	// maxCallsInRequest bounds the number of method calls in one /jmap/api request.
	maxCallsInRequest = 64
	// maxObjectsInGet / maxObjectsInSet bound per-method object counts (advertised).
	maxObjectsInGet = 1000
	maxObjectsInSet = 1000
	// maxObjectsInQuery caps the number of ids one Email/query returns, so an
	// absent/zero/oversized limit can't return the whole account; clients page
	// with position.
	maxObjectsInQuery = 1000
	// maxAPIRequestSize bounds a /jmap/api request body. The body is a small JSON
	// envelope of method calls (not blob data), so a tight cap is safe and blocks
	// the multi-GB-body amplification vector.
	maxAPIRequestSize = 10 << 20 // 10 MiB
)

func (s *Server) maxSizeUpload() int64 {
	if s.MaxSizeUpload > 0 {
		return s.MaxSizeUpload
	}
	return defaultMaxSizeUpload
}

// Handler returns an http.Handler serving the standard JMAP discovery resource
// plus the compatibility /jmap/session endpoint and protocol resources.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jmap", s.handleSession)
	mux.HandleFunc("/jmap/session", s.handleSession)
	mux.HandleFunc("/jmap/api", s.handleAPI)
	mux.HandleFunc("/jmap/download/", s.handleDownload)
	mux.HandleFunc("/jmap/upload/", s.handleUpload)
	mux.HandleFunc("/jmap/eventsource", s.handleEventSource)
	return mux
}

// handleUpload implements the JMAP upload endpoint (RFC 8620 §6.1): POST raw
// bytes, stored content-addressed in the tenant's blob store, returning a
// blobId ("U<tenantID>-<hash>") the client can reference in Email/set create.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	acc, scope, _, agentCredential, err := s.authAccount(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	if agentCredential {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if s.Blob == nil {
		http.Error(w, "upload not enabled", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenantID := scope.Tenant().ID
	// Stream the (size-bounded) body straight into the blob store rather than
	// buffering it all in memory first — Blob.Put content-addresses via a spooled
	// temp file, so an upload costs no per-request 50 MB heap allocation.
	r.Body = http.MaxBytesReader(w, r.Body, s.maxSizeUpload())
	ref, size, err := s.Blob.Put(r.Context(), tenantID, r.Body)
	if err != nil {
		// A MaxBytesReader overflow surfaces here (via Put's read) as a 413; any
		// other error is a storage failure.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "store blob", http.StatusInternalServerError)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"accountId": strconv.FormatInt(acc.ID(), 10),
		"blobId":    "U" + strconv.FormatInt(tenantID, 10) + "-" + string(ref),
		"type":      ct,
		"size":      size,
	})
}

// handleEventSource implements the JMAP push channel (RFC 8620 §7.3) as
// Server-Sent Events. Push only announces a new state; clients still use
// Email/changes to recover the authoritative delta, including after reconnects.
func (s *Server) handleEventSource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	acc, _, _, _, err := s.authAccount(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	options, err := parseEventSourceOptions(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	comm := acc.RegisterComm()
	defer comm.Close()

	accID := strconv.FormatInt(acc.ID(), 10)
	writeStateValue := func(st string) {
		fmt.Fprintf(w, "id: %s\nevent: state\ndata: {\"@type\":\"StateChange\",\"changed\":{\"%s\":{\"Email\":\"%s\"}}}\n\n", st, accID, st)
		flusher.Flush()
	}
	writeCurrentState := func() bool {
		st, stateErr := accountState(r.Context(), acc)
		if stateErr != nil {
			return false
		}
		writeStateValue(st)
		return true
	}

	// Send the current state to a fresh subscriber. When a standards-compliant
	// EventSource client reconnects with that same Last-Event-ID, wait for the
	// next change instead of immediately closing closeafter=state in a busy loop.
	if options.email {
		if initialState, stateErr := accountState(r.Context(), acc); stateErr == nil && r.Header.Get("Last-Event-ID") != initialState {
			writeStateValue(initialState)
			if options.closeAfterState {
				return
			}
		}
	}

	var pingTimer *time.Timer
	var pingC <-chan time.Time
	if options.pingSeconds > 0 {
		pingTimer = time.NewTimer(time.Duration(options.pingSeconds) * time.Second)
		pingC = pingTimer.C
		defer pingTimer.Stop()
	}
	resetPing := func() {
		if pingTimer == nil {
			return
		}
		if !pingTimer.Stop() {
			select {
			case <-pingTimer.C:
			default:
			}
		}
		pingTimer.Reset(time.Duration(options.pingSeconds) * time.Second)
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-pingC:
			fmt.Fprintf(w, "event: ping\ndata: {\"interval\":%d}\n\n", options.pingSeconds)
			flusher.Flush()
			resetPing()
		case _, ok := <-comm.Changes:
			if !ok {
				return
			}
			if !options.email || !writeCurrentState() {
				continue
			}
			if options.closeAfterState {
				return
			}
			resetPing()
		}
	}
}

type eventSourceOptions struct {
	email           bool
	closeAfterState bool
	pingSeconds     int
}

func parseEventSourceOptions(r *http.Request) (eventSourceOptions, error) {
	query := r.URL.Query()
	// Compatibility for older clients that used the pre-template endpoint.
	if !query.Has("types") && !query.Has("closeafter") && !query.Has("ping") {
		return eventSourceOptions{email: true}, nil
	}

	typesValue := query.Get("types")
	if typesValue == "" {
		return eventSourceOptions{}, errors.New("types is required")
	}
	email := typesValue == "*"
	if !email {
		for _, typeName := range strings.Split(typesValue, ",") {
			if typeName == "" {
				return eventSourceOptions{}, errors.New("types contains an empty type")
			}
			if typeName == "Email" {
				email = true
			}
		}
	}

	closeAfter := query.Get("closeafter")
	if closeAfter != "state" && closeAfter != "no" {
		return eventSourceOptions{}, errors.New("closeafter must be state or no")
	}

	pingValue := query.Get("ping")
	pingSeconds, err := strconv.Atoi(pingValue)
	if err != nil || pingSeconds < 0 {
		return eventSourceOptions{}, errors.New("ping must be a non-negative integer")
	}
	// RFC 8620 permits clamping. A five-minute ceiling keeps intermediaries and
	// clients able to detect dead connections without imposing a large idle gap.
	if pingSeconds > 300 {
		pingSeconds = 300
	}

	return eventSourceOptions{
		email:           email,
		closeAfterState: closeAfter == "state",
		pingSeconds:     pingSeconds,
	}, nil
}

// handleDownload serves raw message bytes for a blobId (RFC 8620 §6.2). The
// blobId here is the Email id ("E<emailID>"); the account is verified via Basic
// auth. Path: /jmap/download/{accountId}/{blobId}/{name}.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	acc, _, _, _, err := s.authAccount(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	// Parse /jmap/download/<accountId>/<blobId>/<name>.
	rest := strings.TrimPrefix(r.URL.Path, "/jmap/download/")
	segs := strings.SplitN(rest, "/", 3)
	if len(segs) < 2 {
		http.Error(w, "bad download path", http.StatusBadRequest)
		return
	}
	blobID := segs[1]
	// Resolve the message inside the tx, then STREAM its bytes to the client in
	// bounded chunks — never buffer the whole (potentially large) message in memory
	// (an unauthenticated-size DoS multiplier). Mirrors webapi's raw-message stream.
	var msg store.Message
	err = acc.ReadTx(r.Context(), func(tx store.Tx) error {
		group, ok := s.emailGroup(tx, acc, blobID)
		if !ok {
			return errNotFoundJMAP
		}
		msg = group[0]
		return nil
	})
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	br := acc.MessageReader(r.Context(), msg)
	defer br.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 32*1024)
	for {
		n, e := br.Read(buf)
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

// authAccount extracts the account from the request's credentials via the
// directory. It accepts either an API key (Authorization: Bearer omk_...) or
// HTTP Basic auth (login + password). Both resolve to the same
// (account, scope, login) tuple, so every endpoint handles them uniformly. It
// throttles by client IP: refusing once the per-IP failed-attempt window is
// exceeded and counting each failure, to bound brute-force and enumeration.
func (s *Server) authAccount(r *http.Request) (store.Account, directory.TenantScope, string, bool, error) {
	ip := clientIP(r)
	if s.LoginLimiter != nil && ip != nil && !s.LoginLimiter.CanAdd(ip, time.Now(), 1) {
		return nil, nil, "", false, errRateLimited
	}
	acc, scope, login, agentCredential, err := s.authAccountInner(r)
	if err != nil && s.LoginLimiter != nil && ip != nil {
		s.LoginLimiter.Add(ip, time.Now(), 1) // count only failures
	}
	return acc, scope, login, agentCredential, err
}

// errRateLimited is returned by authAccount when the per-IP attempt window is
// exhausted, so callers can answer 429 rather than 401 (a throttled client is
// not necessarily unauthenticated, and 429 tells it to back off).
var errRateLimited = errors.New("too many authentication attempts")

// writeAuthErr renders an authAccount failure: a rate-limit rejection is 429,
// anything else is a generic 401 (no internal detail).
func writeAuthErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errRateLimited) {
		http.Error(w, "too many authentication attempts", http.StatusTooManyRequests)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// clientIP extracts the client IP from RemoteAddr. It does NOT trust
// X-Forwarded-For (a client could spoof its rate-limit key); a fronting proxy
// must set RemoteAddr or limit itself.
func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (s *Server) authAccountInner(r *http.Request) (store.Account, directory.TenantScope, string, bool, error) {
	// API key first: Authorization: Bearer omk_<prefix>_<secret>.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omk_") {
		token := strings.TrimPrefix(h, "Bearer ")
		scope, princ, accountID, err := s.Dir.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return nil, nil, "", false, err
		}
		// Open the account the key was BOUND to at issuance (accountID), not one
		// re-derived from the login address — an address repointed to a different
		// account after issuance must not silently change which account the key acts
		// as.
		acc, err := scope.AccountForID(r.Context(), accountID)
		if err != nil {
			return nil, nil, "", false, err
		}
		return acc, scope, princ.Login, false, nil
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer omb_") {
		token := strings.TrimPrefix(h, "Bearer ")
		agentDir, ok := s.Dir.(directory.AgentAuthorizationDirectory)
		if !ok {
			return nil, nil, "", false, errors.New("agent credentials are not supported")
		}
		scope, principal, accountID, _, err := agentDir.AuthenticateAgentCredential(r.Context(), token)
		if err != nil {
			return nil, nil, "", false, err
		}
		acc, err := scope.AccountForID(r.Context(), accountID)
		if err != nil {
			return nil, nil, "", false, err
		}
		return acc, scope, principal.Login, true, nil
	}

	login, password, ok := r.BasicAuth()
	if !ok {
		return nil, nil, "", false, fmt.Errorf("missing credentials")
	}
	addr, err := smtp.ParseAddress(login)
	if err != nil {
		return nil, nil, "", false, err
	}
	scope, _, err := s.Dir.AuthenticatePrincipal(r.Context(), login, directory.PasswordCredential(password))
	if err != nil {
		return nil, nil, "", false, err
	}
	acc, err := scope.AccountForAddress(r.Context(), addr.Path())
	if err != nil {
		return nil, nil, "", false, err
	}
	return acc, scope, login, false, nil
}

// accountState returns the account's current changelog head as a JMAP state
// string. It reads the head directly (not via a mutating Tx), so querying state
// never advances it.
func accountState(ctx context.Context, acc store.Account) (string, error) {
	head, err := acc.ChangelogHead(ctx)
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(int64(head), 10), nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	acc, scope, login, agentCredential, err := s.authAccount(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	accID := strconv.FormatInt(acc.ID(), 10)
	session := map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":     s.maxSizeUpload(),
				"maxCallsInRequest": maxCallsInRequest,
				"maxObjectsInGet":   maxObjectsInGet,
				"maxObjectsInSet":   maxObjectsInSet,
			},
			"urn:ietf:params:jmap:mail":             map[string]any{},
			"urn:ietf:params:jmap:vacationresponse": map[string]any{},
		},
		"accounts": map[string]any{
			accID: map[string]any{
				"name":       login,
				"isPersonal": true,
				"isReadOnly": agentCredential,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":             map[string]any{},
					"urn:ietf:params:jmap:vacationresponse": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]any{
			"urn:ietf:params:jmap:mail": accID,
		},
		"username":       login,
		"apiUrl":         s.BaseURL + "/jmap/api",
		"downloadUrl":    s.BaseURL + "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"uploadUrl":      s.BaseURL + "/jmap/upload/{accountId}/",
		"eventSourceUrl": s.BaseURL + "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
		"state":          "0",
	}
	_ = scope
	writeJSON(w, http.StatusOK, session)
}

// Request is a JMAP API request (RFC 8620 §3.3).
type Request struct {
	Using       []string             `json:"using"`
	MethodCalls [][3]json.RawMessage `json:"methodCalls"`
}

// invocation is one [name, args, callId] triple, decoded.
type invocation struct {
	name   string
	args   map[string]json.RawMessage
	callID string
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	acc, scope, login, agentCredential, err := s.authAccount(r)
	if err != nil {
		writeAuthErr(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIRequestSize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader trips this once the body exceeds the cap.
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Enforce the advertised batch cap before dispatching any call, so a huge
	// methodCalls array can't amplify into thousands of queries.
	if len(req.MethodCalls) > maxCallsInRequest {
		http.Error(w, "too many method calls", http.StatusRequestEntityTooLarge)
		return
	}

	var responses [][3]any
	for _, mc := range req.MethodCalls {
		var name, callID string
		_ = json.Unmarshal(mc[0], &name)
		_ = json.Unmarshal(mc[2], &callID)
		var args map[string]json.RawMessage
		_ = json.Unmarshal(mc[1], &args)
		inv := invocation{name: name, args: args, callID: callID}

		resName, resArgs := s.dispatch(r.Context(), acc, scope, login, agentCredential, inv)
		responses = append(responses, [3]any{resName, resArgs, callID})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"methodResponses": responses,
	})
}

// dispatch runs one JMAP method call, returning the response name and args.
func (s *Server) dispatch(ctx context.Context, acc store.Account, scope directory.TenantScope, login string, agentCredential bool, inv invocation) (string, any) {
	// Enforce the advertised per-call object caps centrally, before any method
	// runs, so no handler can drift from the maxObjectsInGet/Set the session
	// advertises. A /get reads N ids; a /set mutates create+update+destroy
	// objects. Exceeding the cap is RFC 8620 "requestTooLarge".
	if n := invGetCount(inv); n > maxObjectsInGet {
		return "error", map[string]any{"type": "requestTooLarge", "description": "too many objects requested"}
	}
	if n := invSetCount(inv); n > maxObjectsInSet {
		return "error", map[string]any{"type": "requestTooLarge", "description": "too many objects in set"}
	}
	if agentCredential && !agentJMAPReadMethod(inv.name) {
		return "error", map[string]any{"type": "forbidden", "description": "Agent mail credentials are read-only on JMAP; use confirmation-controlled mail operations for mutations"}
	}
	switch inv.name {
	case "Mailbox/get":
		return s.mailboxGet(ctx, acc, inv)
	case "Email/query":
		return s.emailQuery(ctx, acc, inv)
	case "Email/get":
		return s.emailGet(ctx, acc, inv)
	case "Email/changes":
		return s.emailChanges(ctx, acc, inv)
	case "Email/set":
		return s.emailSet(ctx, acc, inv)
	case "Thread/get":
		return s.threadGet(ctx, acc, inv)
	case "Mailbox/set":
		return s.mailboxSet(ctx, acc, inv)
	case "Email/copy":
		return s.emailCopy(ctx, acc, inv)
	case "Identity/get":
		return s.identityGet(ctx, acc, login, inv)
	case "SearchSnippet/get":
		return s.searchSnippetGet(ctx, acc, inv)
	case "VacationResponse/get":
		return s.vacationGet(ctx, acc, inv)
	case "VacationResponse/set":
		return s.vacationSet(ctx, acc, inv)
	case "EmailSubmission/set":
		return s.emailSubmissionSet(ctx, acc, scope, login, inv)
	default:
		return "error", map[string]any{"type": "unknownMethod"}
	}
}

func agentJMAPReadMethod(name string) bool {
	switch name {
	case "Mailbox/get", "Email/query", "Email/get", "Email/changes", "Thread/get", "Identity/get", "SearchSnippet/get", "VacationResponse/get":
		return true
	default:
		return false
	}
}

// jsonLen counts the elements of a JSON array (for "ids") or the members of a
// JSON object (for "create"/"update"/"destroy"), without materializing them —
// so a huge id list is rejected before it is unmarshaled into a slice/map.
// Returns 0 for absent/unparseable args.
func jsonLen(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	// Arrays decode into []json.RawMessage; objects into map[string]json.RawMessage.
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return len(arr)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		return len(obj)
	}
	return 0
}

// invGetCount returns the number of objects a /get-family call would fetch.
func invGetCount(inv invocation) int {
	return jsonLen(inv.args["ids"]) + jsonLen(inv.args["emailIds"])
}

// invSetCount returns the number of objects a /set-family call would mutate
// (create + update + destroy).
func invSetCount(inv invocation) int {
	return jsonLen(inv.args["create"]) + jsonLen(inv.args["update"]) + jsonLen(inv.args["destroy"])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
