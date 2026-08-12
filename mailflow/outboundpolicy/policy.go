// Package outboundpolicy defines the storage-neutral business-policy boundary
// for Agent-originated outbound mail. Authentication, authorization and hard
// system limits remain outside this package.
package outboundpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const (
	OutcomeAllow               = "allow"
	OutcomeOwnerReviewRequired = "owner_review_required"

	SourceOwnerDirect      = "owner_direct"
	SourceInboundAutoReply = "inbound_auto_reply"
)

// Intent is the canonical, identity-independent content presented to business
// policy. The authenticated account and credential remain protocol context and
// are deliberately not client-selectable fields here.
type Intent struct {
	Source          string   `json:"source"`
	Operation       string   `json:"operation"`
	SourceEmailID   string   `json:"sourceEmailId,omitempty"`
	To              []string `json:"to"`
	Cc              []string `json:"cc,omitempty"`
	Bcc             []string `json:"bcc,omitempty"`
	Subject         string   `json:"subject"`
	Text            string   `json:"text,omitempty"`
	HTML            string   `json:"html,omitempty"`
	AttachmentCount int      `json:"attachmentCount,omitempty"`
}

type Reason struct {
	Code        string `json:"code"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type Decision struct {
	Outcome       string   `json:"outcome"`
	PolicyVersion string   `json:"policyVersion"`
	Reasons       []Reason `json:"reasons"`
}

type Evaluator interface {
	Evaluate(context.Context, Intent) (Decision, error)
}

// KeywordEvaluator is a deterministic local workflow adapter. It is not the
// final product rule set; callers can replace it through the Evaluator seam.
type KeywordEvaluator struct {
	terms   []string
	version string
}

func NewKeywordEvaluator(rawTerms []string) *KeywordEvaluator {
	seen := map[string]struct{}{}
	terms := make([]string, 0, len(rawTerms))
	for _, raw := range rawTerms {
		term := strings.ToLower(strings.TrimSpace(raw))
		if term == "" {
			continue
		}
		if _, ok := seen[term]; ok {
			continue
		}
		seen[term] = struct{}{}
		terms = append(terms, term)
	}
	sort.Strings(terms)
	digest := sha256.Sum256([]byte(strings.Join(terms, "\x00")))
	return &KeywordEvaluator{
		terms:   terms,
		version: "local-keyword-v1-" + hex.EncodeToString(digest[:6]),
	}
}

func (e *KeywordEvaluator) Evaluate(_ context.Context, intent Intent) (Decision, error) {
	if e == nil || len(e.terms) == 0 {
		return Decision{Outcome: OutcomeAllow, PolicyVersion: "allow-all-v1", Reasons: []Reason{}}, nil
	}
	haystack := strings.ToLower(strings.Join([]string{intent.Subject, intent.Text, intent.HTML}, "\n"))
	for _, term := range e.terms {
		if strings.Contains(haystack, term) {
			return Decision{
				Outcome:       OutcomeOwnerReviewRequired,
				PolicyVersion: e.version,
				Reasons: []Reason{{
					Code:        "configured_review_term",
					Title:       "Owner review required",
					Description: "Outbound content matched the configured review term: " + term,
				}},
			}, nil
		}
	}
	return Decision{Outcome: OutcomeAllow, PolicyVersion: e.version, Reasons: []Reason{}}, nil
}

// Digest returns a stable digest for the semantic intent. Protocol callers add
// authenticated account/credential context before using it as an idempotency key.
func Digest(intent Intent) [sha256.Size]byte {
	encoded, _ := json.Marshal(intent)
	return sha256.Sum256(encoded)
}
