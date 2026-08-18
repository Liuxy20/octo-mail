// Package rulemetadata authenticates server-generated Agent Mail forwarding
// metadata. External SMTP headers are untrusted; only a complete tuple signed
// with the deployment's automatic-reply chain key is accepted.
package rulemetadata

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	HeaderOriginalFrom = "X-Octo-Original-From"
	HeaderSentBy       = "X-Octo-Sent-By"
	HeaderRuleID       = "X-Octo-Rule-ID"
	HeaderRuleHop      = "X-Octo-Rule-Hop"
	HeaderRuleTrace    = "X-Octo-Rule-Trace"
	HeaderRecipients   = "X-Octo-Rule-Recipients"
	HeaderExpires      = "X-Octo-Rule-Expires"
	HeaderSignature    = "X-Octo-Rule-Signature"

	signatureVersion       = "v3"
	legacySignatureVersion = "v2"
	minKeyBytes            = 32
	maxAddressBytes        = 320
	maxHop                 = 1_000_000
	signatureValidity      = 24 * time.Hour
	clockSkew              = 5 * time.Minute
)

// Metadata is the complete server-owned rule-forwarding tuple. MessageID binds
// the signature to the concrete generated message rather than just a rule.
type Metadata struct {
	OriginalFrom string
	SentBy       string
	RuleID       int64
	Hop          int
	RuleTrace    []int64
	MessageID    string
	Recipients   []string
	ExpiresAt    int64
	// ChainTrusted is set only after a content-bound v3 signature verifies.
	// Legacy v2 metadata remains readable for attribution, but cannot grant
	// permission to continue an automatic-reply or forwarding chain.
	ChainTrusted bool
}

// Authenticator signs and verifies metadata with a deployment-wide key.
type Authenticator struct {
	key []byte
}

func New(key []byte) (*Authenticator, error) {
	if len(key) < minKeyBytes {
		return nil, fmt.Errorf("rule metadata key must contain at least %d bytes", minKeyBytes)
	}
	return &Authenticator{key: bytes.Clone(key)}, nil
}

func (a *Authenticator) Sign(metadata Metadata, raw []byte) (string, error) {
	metadata, err := canonicalMetadata(metadata)
	if err != nil {
		return "", err
	}
	header, contentDigest, ok := messageContentDigest(raw)
	if !ok {
		return "", errors.New("invalid forwarded message content")
	}
	messageID, ok := singleHeader(header, "Message-ID")
	if !ok || messageID != metadata.MessageID {
		return "", errors.New("forwarded message id does not match rule metadata")
	}
	return signatureVersion + "." + base64.RawURLEncoding.EncodeToString(a.mac(metadata, signatureVersion, contentDigest)), nil
}

// Verify checks a raw RFC 5322 message. Missing, partial, duplicated, malformed,
// or tampered metadata is rejected as one unit.
func (a *Authenticator) Verify(raw []byte, expectedRecipient string, now time.Time) (Metadata, bool) {
	return a.VerifyAny(raw, []string{expectedRecipient}, now)
}

// VerifyAny accepts metadata only when at least one account address is included
// in the signed recipient set. This lets aliases retain trust without widening
// it beyond addresses that actually belong to the receiving account.
func (a *Authenticator) VerifyAny(raw []byte, expectedRecipients []string, now time.Time) (Metadata, bool) {
	header, contentDigest, ok := messageContentDigest(raw)
	if !ok {
		return Metadata{}, false
	}
	return a.verifyHeader(header, expectedRecipients, now, contentDigest)
}

func (a *Authenticator) verifyHeader(header textproto.MIMEHeader, expectedRecipients []string, now time.Time, contentDigest [sha256.Size]byte) (Metadata, bool) {
	originalFrom, ok := singleHeader(header, HeaderOriginalFrom)
	if !ok {
		return Metadata{}, false
	}
	sentBy, ok := singleHeader(header, HeaderSentBy)
	if !ok {
		return Metadata{}, false
	}
	ruleIDText, ok := singleHeader(header, HeaderRuleID)
	if !ok {
		return Metadata{}, false
	}
	hopText, ok := singleHeader(header, HeaderRuleHop)
	if !ok {
		return Metadata{}, false
	}
	messageID, ok := singleHeader(header, "Message-ID")
	if !ok {
		return Metadata{}, false
	}
	recipientsText, ok := singleHeader(header, HeaderRecipients)
	if !ok {
		return Metadata{}, false
	}
	expiresText, ok := singleHeader(header, HeaderExpires)
	if !ok {
		return Metadata{}, false
	}
	signatureText, ok := singleHeader(header, HeaderSignature)
	if !ok {
		return Metadata{}, false
	}
	ruleID, err := strconv.ParseInt(ruleIDText, 10, 64)
	if err != nil {
		return Metadata{}, false
	}
	hop, err := strconv.Atoi(hopText)
	if err != nil {
		return Metadata{}, false
	}
	expiresAt, err := strconv.ParseInt(expiresText, 10, 64)
	if err != nil || expiresAt <= now.Unix() || expiresAt > now.Add(signatureValidity+clockSkew).Unix() {
		return Metadata{}, false
	}
	version, signature, ok := decodeSignature(signatureText)
	if !ok {
		return Metadata{}, false
	}
	traceText := ""
	if version == signatureVersion {
		var traceOK bool
		traceText, traceOK = singleHeader(header, HeaderRuleTrace)
		if !traceOK {
			return Metadata{}, false
		}
	}
	metadata := Metadata{
		OriginalFrom: originalFrom,
		SentBy:       sentBy,
		RuleID:       ruleID,
		Hop:          hop,
		MessageID:    messageID,
		ExpiresAt:    expiresAt,
	}
	metadata, err = canonicalScalarMetadata(metadata)
	if err != nil {
		return Metadata{}, false
	}
	// Authenticate the bounded scalar fields plus the raw trace and recipient
	// lists before splitting either attacker-controlled list. Server-generated
	// messages always use the same canonical strings when signing.
	if !hmac.Equal(signature, a.macFields(metadata, version, traceText, recipientsText, contentDigest)) {
		return Metadata{}, false
	}
	metadata.Recipients = strings.Split(recipientsText, ",")
	metadata, err = canonicalBaseMetadata(metadata)
	if err != nil {
		return Metadata{}, false
	}
	if !containsAnyRecipient(metadata.Recipients, expectedRecipients) {
		return Metadata{}, false
	}
	if version == signatureVersion {
		metadata.RuleTrace, err = parseRuleTrace(traceText)
		if err != nil {
			return Metadata{}, false
		}
		metadata, err = canonicalMetadata(metadata)
		if err != nil {
			return Metadata{}, false
		}
	} else {
		// v2 remains verifiable for attribution only. It did not authenticate
		// content, so it must not authorize continuation of a rule chain.
		metadata.RuleTrace = []int64{ruleID}
	}
	metadata.ChainTrusted = version == signatureVersion
	return metadata, true
}

func (a *Authenticator) mac(metadata Metadata, version string, contentDigest [sha256.Size]byte) []byte {
	traceText := ""
	if version == signatureVersion {
		traceText = formatRuleTrace(metadata.RuleTrace)
	}
	return a.macFields(metadata, version, traceText, strings.Join(metadata.Recipients, ","), contentDigest)
}

func (a *Authenticator) macFields(metadata Metadata, version, traceText, recipientsText string, contentDigest [sha256.Size]byte) []byte {
	mac := hmac.New(sha256.New, a.key)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%s\n%d\n%d\n%s",
		version, metadata.OriginalFrom, metadata.SentBy,
		metadata.RuleID, metadata.Hop, metadata.MessageID)
	if version == signatureVersion {
		_, _ = fmt.Fprintf(mac, "\n%s", traceText)
		_, _ = mac.Write(contentDigest[:])
	}
	_, _ = fmt.Fprintf(mac, "\n%s\n%d", recipientsText, metadata.ExpiresAt)
	return mac.Sum(nil)
}

func canonicalMetadata(metadata Metadata) (Metadata, error) {
	metadata.ChainTrusted = false
	metadata, err := canonicalBaseMetadata(metadata)
	if err != nil {
		return Metadata{}, err
	}
	if len(metadata.RuleTrace) == 0 || len(metadata.RuleTrace) > maxHop || metadata.Hop != len(metadata.RuleTrace) {
		return Metadata{}, errors.New("invalid rule trace length")
	}
	seenRules := make(map[int64]struct{}, len(metadata.RuleTrace))
	for _, ruleID := range metadata.RuleTrace {
		if ruleID <= 0 {
			return Metadata{}, errors.New("invalid rule trace identity")
		}
		if _, exists := seenRules[ruleID]; exists {
			return Metadata{}, errors.New("duplicate rule trace identity")
		}
		seenRules[ruleID] = struct{}{}
	}
	if metadata.RuleTrace[len(metadata.RuleTrace)-1] != metadata.RuleID {
		return Metadata{}, errors.New("rule trace does not end with signing rule")
	}
	return metadata, nil
}

func canonicalBaseMetadata(metadata Metadata) (Metadata, error) {
	metadata, err := canonicalScalarMetadata(metadata)
	if err != nil {
		return Metadata{}, err
	}
	canonicalRecipients, err := canonicalizeRecipients(metadata.Recipients)
	if err != nil {
		return Metadata{}, err
	}
	metadata.Recipients = canonicalRecipients
	return metadata, nil
}

func canonicalScalarMetadata(metadata Metadata) (Metadata, error) {
	metadata.ChainTrusted = false
	metadata.OriginalFrom = strings.TrimSpace(metadata.OriginalFrom)
	metadata.SentBy = strings.TrimSpace(metadata.SentBy)
	metadata.MessageID = strings.TrimSpace(metadata.MessageID)
	if metadata.OriginalFrom == "" || metadata.SentBy == "" ||
		len(metadata.OriginalFrom) > maxAddressBytes || len(metadata.SentBy) > maxAddressBytes ||
		strings.ContainsAny(metadata.OriginalFrom, "\r\n") || strings.ContainsAny(metadata.SentBy, "\r\n") {
		return Metadata{}, errors.New("invalid rule attribution address")
	}
	if metadata.RuleID <= 0 || metadata.Hop < 0 || metadata.Hop > maxHop {
		return Metadata{}, errors.New("invalid rule identity or hop")
	}
	if !validMessageID(metadata.MessageID) {
		return Metadata{}, errors.New("invalid rule metadata Message-ID")
	}
	if metadata.ExpiresAt <= 0 {
		return Metadata{}, errors.New("invalid rule metadata expiry")
	}
	return metadata, nil
}

func canonicalizeRecipients(recipients []string) ([]string, error) {
	canonicalRecipients := make([]string, 0, len(recipients))
	seen := map[string]bool{}
	for _, recipient := range recipients {
		recipient = canonicalAddress(recipient)
		if recipient == "" {
			return nil, errors.New("invalid rule metadata recipient")
		}
		if !seen[recipient] {
			seen[recipient] = true
			canonicalRecipients = append(canonicalRecipients, recipient)
		}
	}
	if len(canonicalRecipients) == 0 {
		return nil, errors.New("missing rule metadata recipient")
	}
	sort.Strings(canonicalRecipients)
	return canonicalRecipients, nil
}

func Expiry(now time.Time) int64 { return now.Add(signatureValidity).Unix() }

func CanonicalRecipients(recipients []string) (string, error) {
	canonical, err := canonicalizeRecipients(recipients)
	if err != nil {
		return "", err
	}
	return strings.Join(canonical, ","), nil
}

func FormatRuleTrace(trace []int64) (string, error) {
	if len(trace) == 0 || len(trace) > maxHop {
		return "", errors.New("invalid rule trace length")
	}
	seen := make(map[int64]struct{}, len(trace))
	for _, ruleID := range trace {
		if ruleID <= 0 {
			return "", errors.New("invalid rule trace identity")
		}
		if _, exists := seen[ruleID]; exists {
			return "", errors.New("duplicate rule trace identity")
		}
		seen[ruleID] = struct{}{}
	}
	return formatRuleTrace(trace), nil
}

func formatRuleTrace(trace []int64) string {
	values := make([]string, len(trace))
	for i, ruleID := range trace {
		values[i] = strconv.FormatInt(ruleID, 10)
	}
	return strings.Join(values, ",")
}

func parseRuleTrace(value string) ([]int64, error) {
	if value == "" {
		return nil, errors.New("empty rule trace")
	}
	// Count separators before allocating any trace-sized data. The count is
	// bounded by the same existing metadata limit; parsing below remains
	// incremental and never materializes a strings.Split result.
	if strings.Count(value, ",") >= maxHop {
		return nil, errors.New("rule trace exceeds limit")
	}
	trace := make([]int64, 0, 8)
	seen := make(map[int64]struct{})
	for {
		if len(trace) >= maxHop {
			return nil, errors.New("rule trace exceeds limit")
		}
		part := value
		if separator := strings.IndexByte(value, ','); separator >= 0 {
			part = value[:separator]
			value = value[separator+1:]
			if value == "" {
				return nil, errors.New("invalid rule trace identity")
			}
		} else {
			value = ""
		}
		ruleID, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || ruleID <= 0 {
			return nil, errors.New("invalid rule trace identity")
		}
		if _, exists := seen[ruleID]; exists {
			return nil, errors.New("duplicate rule trace identity")
		}
		seen[ruleID] = struct{}{}
		trace = append(trace, ruleID)
		if value == "" {
			break
		}
	}
	return trace, nil
}

var contentBoundHeaders = []string{
	"From", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date",
	"Auto-Submitted", "MIME-Version", "Content-Type",
	"Content-Transfer-Encoding", "Content-Disposition", "In-Reply-To", "References",
}

// messageContentDigest binds the fields that control reply routing, rule
// matching, MIME interpretation, and the complete MIME body. Transport-added
// headers such as Received and DKIM-Signature are deliberately excluded.
func messageContentDigest(raw []byte) (textproto.MIMEHeader, [sha256.Size]byte, bool) {
	reader := bufio.NewReader(bytes.NewReader(raw))
	header, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		return nil, [sha256.Size]byte{}, false
	}
	digest := sha256.New()
	for _, name := range contentBoundHeaders {
		writeDigestValue(digest, name)
		values := header.Values(name)
		var count [8]byte
		binary.BigEndian.PutUint64(count[:], uint64(len(values)))
		_, _ = digest.Write(count[:])
		for _, value := range values {
			writeDigestValue(digest, strings.TrimSpace(value))
		}
	}
	if _, err := io.Copy(digest, reader); err != nil {
		return nil, [sha256.Size]byte{}, false
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return header, result, true
}

func writeDigestValue(w io.Writer, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = w.Write(size[:])
	_, _ = io.WriteString(w, value)
}

func canonicalAddress(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > maxAddressBytes || !strings.Contains(value, "@") || strings.ContainsAny(value, "\r\n\t ,") {
		return ""
	}
	return value
}

func containsAnyRecipient(recipients, expectedRecipients []string) bool {
	for _, expected := range expectedRecipients {
		expected = canonicalAddress(expected)
		if expected == "" {
			continue
		}
		for _, recipient := range recipients {
			if recipient == expected {
				return true
			}
		}
	}
	return false
}

func singleHeader(header textproto.MIMEHeader, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	return value, value != ""
}

func decodeSignature(value string) (string, []byte, bool) {
	for _, version := range []string{signatureVersion, legacySignatureVersion} {
		prefix := version + "."
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
		return version, raw, err == nil && len(raw) == sha256.Size
	}
	return "", nil, false
}

func validMessageID(value string) bool {
	return len(value) >= 3 && value[0] == '<' && value[len(value)-1] == '>' &&
		!strings.ContainsAny(value, "\r\n\t ")
}
