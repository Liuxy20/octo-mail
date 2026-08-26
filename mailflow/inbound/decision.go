// Package inbound's decision engine combines greylisting, per-recipient sender
// reputation, and bayesian junk scoring into a single inbound verdict — the
// octo-mail equivalent of the smtpserver/analyze.go + reputation.go, implemented
// on the Postgres substrate rather than bstore. The verdict is computed AFTER
// DATA (content available). Content and reputation can only route accepted mail
// into Junk; protocol/security checks remain responsible for SMTP rejection.
package inbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Verdict is the inbound decision for one message.
type Verdict int

const (
	Accept     Verdict = iota // deliver to Inbox
	AcceptJunk                // deliver to Junk mailbox
	Defer                     // temporary 4xx (greylist) — client should retry
	Reject                    // permanent 5xx
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "accept"
	case AcceptJunk:
		return "junk"
	case Defer:
		return "defer"
	case Reject:
		return "reject"
	}
	return "unknown"
}

// Decision carries the verdict plus a human-readable reason (for logs/AR).
type Decision struct {
	Verdict Verdict
	Reason  string
	// Mailbox, when non-empty, overrides the destination mailbox (a ruleset match
	// forcing delivery to e.g. "Lists"). Empty means the default (Inbox/Junk).
	Mailbox string
}

// Decider makes inbound accept/defer/reject decisions. It is safe to leave any
// knob at zero for sensible defaults.
type Decider struct {
	Pool *pgxpool.Pool

	// GreylistDelay is how long a first-seen triplet is deferred (default 5m).
	GreylistDelay time.Duration
	// GreylistEnabled turns greylisting on. Off by default (opt-in) because it
	// adds delivery latency for first contacts.
	GreylistEnabled bool

	// TrustedHamCount: a sender domain with at least this many accepted (ham)
	// messages and no junk skips content-based Junk routing (default 3).
	TrustedHamCount int64
}

// ClassifyFunc returns the shared Bayesian result for a recipient. Content
// classification is only allowed to route accepted mail into Junk.
type ClassifyFunc func(ctx context.Context, accountID int64, raw []byte) (prob float64, significant, isJunk bool, err error)

func (d *Decider) greylistDelay() time.Duration {
	if d.GreylistDelay > 0 {
		return d.GreylistDelay
	}
	return 5 * time.Minute
}
func (d *Decider) trustedHam() int64 {
	if d.TrustedHamCount > 0 {
		return d.TrustedHamCount
	}
	return 3
}

// Decide computes the inbound verdict for a message to accountID from
// senderDomain/clientIP, given the auth result and a junk classifier. Order:
//  1. authentication-based hard reject (DMARC handled by caller earlier);
//  2. an authenticated explicit sender allowlist match → Accept;
//  3. reputation: enough ham + no junk → Accept (trusted, skip content checks);
//     enough junk + no ham → AcceptJunk;
//  4. greylist first-seen triplets → Defer;
//  5. content (bayesian): spam → AcceptJunk;
//  6. otherwise Accept.
//
// authed reports whether senderDomain (the reputation key) is itself
// authenticated for this message — i.e. the caller verified the exact
// senderDomain (e.g. an SPF pass on that envelope domain), not merely some
// aligned identity. Reputation is only credited/consulted for authenticated
// domains: an unauthenticated MAIL FROM domain is trivially spoofable, so
// letting it earn or leverage reputation would let an attacker bypass
// greylist+content by forging a trusted domain (and let benign first-contacts
// poison an unknown domain). When authed is false, unauthenticated mail still
// flows through greylist + content scoring but gets no trusted-sender fast-path.
// senderAllowed is computed only after the visible From
// identity passes DMARC alignment; callers must not set it for unauthenticated
// mail.
func (d *Decider) Decide(ctx context.Context, accountID int64, senderDomain string, clientIP net.IP, raw []byte, authed, senderAllowed bool, classify ClassifyFunc) Decision {
	// 1. Rulesets: a per-account header match can force a destination mailbox and
	//    (by default) accept unconditionally, bypassing reputation/content checks.
	if rs, ok := d.matchRuleset(ctx, accountID, raw); ok {
		if rs.forceAccept {
			return Decision{Verdict: Accept, Reason: "ruleset", Mailbox: rs.mailbox}
		}
		// Forwarded messages (the analyze design): the forwarding server's SPF/DMARC
		// and IP reputation don't reflect the true origin, so skip reputation- and
		// content-based rejection — deliver to the ruleset's mailbox (or Inbox).
		if rs.isForward {
			mb := rs.mailbox
			return Decision{Verdict: Accept, Reason: "forwarded", Mailbox: mb}
		}
		// Non-force ruleset: run the checks once; on accept, route to the
		// ruleset's mailbox. Return the single result either way — never re-run
		// decideCore (it mutates greylist state and re-classifies).
		dec := d.decideCore(ctx, accountID, senderDomain, clientIP, raw, authed, senderAllowed, classify)
		if dec.Verdict == Accept || dec.Verdict == AcceptJunk {
			dec.Mailbox = rs.mailbox
		}
		return dec
	}
	return d.decideCore(ctx, accountID, senderDomain, clientIP, raw, authed, senderAllowed, classify)
}

// decideCore is the explicit allowlist + reputation + greylist + content
// pipeline. Content and reputation may file mail into Junk but never reject it.
func (d *Decider) decideCore(ctx context.Context, accountID int64, senderDomain string, clientIP net.IP, raw []byte, authed, senderAllowed bool, classify ClassifyFunc) Decision {
	// 2. Explicit allowlist, already gated by caller-side DMARC alignment.
	if senderAllowed {
		return Decision{Verdict: Accept, Reason: "allowlisted-sender"}
	}

	// 3. Reputation shortcuts. The ACCEPT (trusted-sender) shortcut is gated on
	//    authentication: an unauthenticated (spoofable) MAIL FROM domain must not
	//    earn or leverage a "trusted" reputation, or an attacker could forge a
	//    domain the recipient trusts to bypass greylist+content. Known-bad
	//    reputation is reversible and therefore routes to Junk instead of
	//    permanently rejecting the message.
	ham, junk := d.reputation(ctx, accountID, senderDomain)
	if authed && ham >= d.trustedHam() && junk == 0 {
		return Decision{Verdict: Accept, Reason: "trusted-sender"}
	}
	if junk >= 3 && ham == 0 {
		return Decision{Verdict: AcceptJunk, Reason: "known-bad-sender"}
	}

	// 4. Greylist first-seen triplets (only for not-yet-trusted senders).
	if d.GreylistEnabled {
		if deferred := d.greylist(ctx, accountID, senderDomain, clientIP); deferred {
			return Decision{Verdict: Defer, Reason: "greylisted"}
		}
	}

	// 5. Shared content scoring. The shared threshold is deliberately
	// conservative and the action is always reversible Junk delivery.
	if classify != nil {
		_, significant, isJunk, err := classify(ctx, accountID, raw)
		if err == nil && significant && isJunk {
			return Decision{Verdict: AcceptJunk, Reason: "junk-content"}
		}
	}
	return Decision{Verdict: Accept, Reason: "clean"}
}

// reputation returns (ham, junk) counts for (account, senderDomain).
func (d *Decider) reputation(ctx context.Context, accountID int64, senderDomain string) (ham, junk int64) {
	_ = d.Pool.QueryRow(ctx,
		`SELECT ham_count, junk_count FROM inbound_reputation WHERE account_id=$1 AND sender_domain=$2`,
		accountID, senderDomain).Scan(&ham, &junk)
	return ham, junk
}

// RecordOutcome updates inbound reputation after a message is filed: ham=true if
// delivered to Inbox, false if to Junk. Called post-delivery. Only records when
// authed is true — reputation must be built from authenticated (DMARC-aligned /
// DKIM-verified) mail only, so an unauthenticated spoofable domain can never
// accrue a "trusted" (or "known-bad") history. A no-op when authed is false.
func (d *Decider) RecordOutcome(ctx context.Context, accountID int64, senderDomain string, authed, ham bool) error {
	if !authed {
		return nil
	}
	col := "junk_count"
	if ham {
		col = "ham_count"
	}
	_, err := d.Pool.Exec(ctx,
		`INSERT INTO inbound_reputation (account_id, sender_domain, `+col+`) VALUES ($1,$2,1)
		 ON CONFLICT (account_id, sender_domain)
		 DO UPDATE SET `+col+` = inbound_reputation.`+col+` + 1, updated_at = now()`,
		accountID, senderDomain)
	return err
}

// greylist returns true if the triplet is first-seen (or still within the delay)
// and should be deferred. On a retry after the delay it records allowed_at and
// returns false. Subnet is /24 (v4) or /64 (v6).
func (d *Decider) greylist(ctx context.Context, accountID int64, senderDomain string, ip net.IP) bool {
	subnet := subnetOf(ip)
	// Compute the triplet's age in SQL (avoids Go/DB clock & timezone skew).
	var ageSecs float64
	var allowedAt *time.Time
	err := d.Pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (now()-first_seen)), allowed_at FROM greylist WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
		accountID, senderDomain, subnet).Scan(&ageSecs, &allowedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// First contact: record and defer.
		_, _ = d.Pool.Exec(ctx,
			`INSERT INTO greylist (account_id, sender_domain, client_subnet) VALUES ($1,$2,$3)
			 ON CONFLICT DO NOTHING`, accountID, senderDomain, subnet)
		return true
	}
	if err != nil {
		// On error, fail open (accept) rather than block mail.
		return false
	}
	if allowedAt != nil {
		return false // already passed greylisting
	}
	if ageSecs >= d.greylistDelay().Seconds() {
		now := time.Now()
		_, _ = d.Pool.Exec(ctx,
			`UPDATE greylist SET allowed_at=$4, count=count+1 WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
			accountID, senderDomain, subnet, now)
		return false
	}
	// Still within the delay window: keep deferring.
	_, _ = d.Pool.Exec(ctx,
		`UPDATE greylist SET count=count+1 WHERE account_id=$1 AND sender_domain=$2 AND client_subnet=$3`,
		accountID, senderDomain, subnet)
	return true
}

// subnetOf returns the greylisting subnet key for an IP (/24 v4, /64 v6).
func subnetOf(ip net.IP) string {
	if ip == nil {
		return "unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ruleset is a matched per-account delivery rule.
type ruleset struct {
	mailbox     string
	forceAccept bool
	isForward   bool
}

// matchRuleset returns the first ruleset (by ord) whose header substring matches
// the message. It parses the message headers with the parser and does a
// case-insensitive substring test on the named header's value.
func (d *Decider) matchRuleset(ctx context.Context, accountID int64, raw []byte) (ruleset, bool) {
	rows, err := d.Pool.Query(ctx,
		`SELECT header_name, header_substr, mailbox, force_accept, is_forward FROM rulesets
		 WHERE account_id=$1 ORDER BY ord, id`, accountID)
	if err != nil {
		return ruleset{}, false
	}
	type rule struct {
		name, substr, mailbox string
		force                 bool
		forward               bool
	}
	var rules []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.name, &r.substr, &r.mailbox, &r.force, &r.forward); err != nil {
			rows.Close()
			return ruleset{}, false
		}
		rules = append(rules, r)
	}
	rows.Close()
	if len(rules) == 0 {
		return ruleset{}, false
	}
	hdrs := parseHeaders(raw)
	for _, r := range rules {
		v := hdrs[strings.ToLower(r.name)]
		if v != "" && strings.Contains(strings.ToLower(v), strings.ToLower(r.substr)) {
			return ruleset{mailbox: r.mailbox, forceAccept: r.force, isForward: r.forward}, true
		}
	}
	return ruleset{}, false
}

// parseHeaders extracts folded header name→value pairs from a raw message (only
// the header block; first value wins per name). Lowercased names as keys.
func parseHeaders(raw []byte) map[string]string {
	s := string(NormalizeEOL(raw))
	end := strings.Index(s, "\r\n\r\n")
	if end < 0 {
		end = len(s)
	}
	head := s[:end]
	// Unfold continuation lines.
	head = strings.ReplaceAll(head, "\r\n\t", "\t")
	head = strings.ReplaceAll(head, "\r\n ", " ")
	out := map[string]string{}
	for _, line := range strings.Split(head, "\r\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if _, ok := out[name]; !ok {
			out[name] = val
		}
	}
	return out
}
