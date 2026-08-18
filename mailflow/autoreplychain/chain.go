// Package autoreplychain implements authenticated, bounded metadata for
// Agent-to-Agent automatic email reply chains. The state travels with the
// message so no workflow database is required, while HMAC authentication keeps
// untrusted senders from forging a limit-reached marker.
package autoreplychain

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	HeaderTraceID   = "X-Octo-Auto-Reply-Trace-ID"
	HeaderCount     = "X-Octo-Auto-Reply-Count"
	HeaderSignature = "X-Octo-Auto-Reply-Signature"
	HeaderRecipient = "X-Octo-Auto-Reply-Recipient"
	HeaderExpires   = "X-Octo-Auto-Reply-Expires"
	HeaderSubmitted = "Auto-Submitted"

	SubmittedAutoReplied = "auto-replied"
	FinalNotice          = "如无明确问题或待办，无需回复。"
	DefaultMaxCount      = 4

	signatureVersion  = "v2"
	minKeyBytes       = 32
	maxTraceIDBytes   = 64
	maxCount          = 1_000_000
	signatureValidity = 24 * time.Hour
	clockSkew         = 5 * time.Minute
)

var (
	ErrLimitReached           = errors.New("automatic reply limit reached")
	ErrExternalAutomatedReply = errors.New("external automated reply must not start a new automatic-reply chain")
)

type Verification uint8

const (
	VerificationMissing Verification = iota
	VerificationValid
	VerificationInvalid
)

type Context struct {
	Verification Verification
	TraceID      string
	Count        int
	Automated    bool
}

type Metadata struct {
	TraceID   string
	Count     int
	Recipient string
	ExpiresAt int64
	Signature string
}

// Chain signs and verifies one deployment's automatic-reply metadata.
// Multiple octo-mail instances must use the same key and maximum.
type Chain struct {
	key      []byte
	maxCount int
}

func New(key []byte, max int) (*Chain, error) {
	if max <= 0 || max > maxCount {
		return nil, fmt.Errorf("auto-reply max count must be between 1 and %d", maxCount)
	}
	if len(key) < minKeyBytes {
		return nil, fmt.Errorf("auto-reply chain key must contain at least %d bytes", minKeyBytes)
	}
	return &Chain{key: bytes.Clone(key), maxCount: max}, nil
}

func (c *Chain) MaxCount() int { return c.maxCount }

// Verify reads the source message's chain metadata. Missing metadata is an
// ordinary external message. Partial, malformed, tampered, or replayed metadata
// is invalid and must never be trusted to suppress a reply.
func (c *Chain) Verify(raw []byte, expectedRecipient string, now time.Time) Context {
	header, err := readHeader(raw)
	if err != nil {
		return Context{Verification: VerificationInvalid}
	}
	context := Context{Automated: automatedHeader(header)}
	traceID, traceOK := singleHeader(header, HeaderTraceID)
	countText, countOK := singleHeader(header, HeaderCount)
	recipient, recipientOK := singleHeader(header, HeaderRecipient)
	expiresText, expiresOK := singleHeader(header, HeaderExpires)
	signatureText, signatureOK := singleHeader(header, HeaderSignature)
	if !traceOK && !countOK && !recipientOK && !expiresOK && !signatureOK {
		context.Verification = VerificationMissing
		return context
	}
	recipient = canonicalRecipient(recipient)
	expectedRecipient = canonicalRecipient(expectedRecipient)
	if !traceOK || !countOK || !recipientOK || !expiresOK || !signatureOK ||
		!validTraceID(traceID) || recipient == "" || recipient != expectedRecipient {
		context.Verification = VerificationInvalid
		return context
	}
	count, err := strconv.Atoi(countText)
	if err != nil || count <= 0 || count > maxCount {
		context.Verification = VerificationInvalid
		return context
	}
	expiresAt, err := strconv.ParseInt(expiresText, 10, 64)
	if err != nil || expiresAt <= now.Unix() || expiresAt > now.Add(signatureValidity+clockSkew).Unix() {
		context.Verification = VerificationInvalid
		return context
	}
	messageID := canonicalMessageID(header.Get("Message-ID"))
	if messageID == "" {
		context.Verification = VerificationInvalid
		return context
	}
	signature, ok := decodeSignature(signatureText)
	if !ok {
		context.Verification = VerificationInvalid
		return context
	}
	want := c.mac(traceID, count, messageID, recipient, expiresAt)
	if !hmac.Equal(signature, want) {
		context.Verification = VerificationInvalid
		return context
	}
	context.Verification = VerificationValid
	context.TraceID = traceID
	context.Count = count
	return context
}

// Next returns metadata for an automatic reply to sourceRaw. Invalid OCTO
// metadata on an otherwise ordinary message starts a new chain and never
// inherits an attacker-controlled count. External automated messages are
// rejected so they cannot reset an automatic-reply loop.
func (c *Chain) Next(sourceRaw []byte, outgoingMessageID, currentRecipient, outgoingRecipient string, now time.Time) (Metadata, Context, error) {
	return c.next(sourceRaw, outgoingMessageID, currentRecipient, outgoingRecipient, now, false)
}

// NextFromTrustedForward starts or continues an automatic-reply chain for a
// forwarding-rule message whose separate rulemetadata signature has already
// been verified by the caller. Ordinary untrusted automated mail must continue
// to use Next so it cannot reset an automatic-reply loop.
func (c *Chain) NextFromTrustedForward(sourceRaw []byte, outgoingMessageID, currentRecipient, outgoingRecipient string, now time.Time) (Metadata, Context, error) {
	return c.next(sourceRaw, outgoingMessageID, currentRecipient, outgoingRecipient, now, true)
}

func (c *Chain) next(sourceRaw []byte, outgoingMessageID, currentRecipient, outgoingRecipient string, now time.Time, trustedForward bool) (Metadata, Context, error) {
	context := c.Verify(sourceRaw, currentRecipient, now)
	if c.BlocksAutomaticReply(context) && !trustedForward {
		return Metadata{}, context, ErrExternalAutomatedReply
	}
	if context.Verification == VerificationValid && context.Count >= c.maxCount {
		return Metadata{}, context, ErrLimitReached
	}
	traceID := context.TraceID
	count := 1
	if context.Verification == VerificationValid {
		count = context.Count + 1
	}
	if traceID == "" {
		var err error
		traceID, err = newTraceID()
		if err != nil {
			return Metadata{}, context, fmt.Errorf("generate auto-reply trace id: %w", err)
		}
	}
	messageID := canonicalMessageID(outgoingMessageID)
	if messageID == "" {
		return Metadata{}, context, errors.New("outgoing Message-ID is required")
	}
	recipient := canonicalRecipient(outgoingRecipient)
	if recipient == "" {
		return Metadata{}, context, errors.New("outgoing recipient is required")
	}
	expiresAt := now.Add(signatureValidity).Unix()
	signature := signatureVersion + "." + base64.RawURLEncoding.EncodeToString(c.mac(traceID, count, messageID, recipient, expiresAt))
	return Metadata{TraceID: traceID, Count: count, Recipient: recipient, ExpiresAt: expiresAt, Signature: signature}, context, nil
}

func (c *Chain) IsFinalCount(count int) bool { return count == c.maxCount }

func (c *Chain) LimitReached(context Context) bool {
	return context.Verification == VerificationValid && context.Count >= c.maxCount
}

func (c *Chain) NextReplyIsFinal(context Context) bool {
	return context.Verification == VerificationValid && context.Count+1 == c.maxCount ||
		context.Verification != VerificationValid && c.maxCount == 1
}

// BlocksAutomaticReply reports an automated source that did not originate from
// a valid OCTO chain. Valid signed Bot-to-Bot replies carry Auto-Submitted too
// and must remain eligible until the configured count is reached.
func (c *Chain) BlocksAutomaticReply(context Context) bool {
	return context.Automated && context.Verification != VerificationValid
}

func Headers(metadata Metadata) map[string]string {
	return map[string]string{
		HeaderSubmitted: SubmittedAutoReplied,
		HeaderTraceID:   metadata.TraceID,
		HeaderCount:     strconv.Itoa(metadata.Count),
		HeaderRecipient: metadata.Recipient,
		HeaderExpires:   strconv.FormatInt(metadata.ExpiresAt, 10),
		HeaderSignature: metadata.Signature,
	}
}

func AppendFinalNotice(text string) string {
	if strings.HasSuffix(strings.TrimSpace(text), FinalNotice) {
		return text
	}
	return strings.TrimRight(text, "\r\n") + "\n\n" + FinalNotice
}

func (c *Chain) mac(traceID string, count int, messageID, recipient string, expiresAt int64) []byte {
	mac := hmac.New(sha256.New, c.key)
	fmt.Fprintf(mac, "%s\n%s\n%d\n%s\n%s\n%d", signatureVersion, traceID, count,
		canonicalMessageID(messageID), canonicalRecipient(recipient), expiresAt)
	return mac.Sum(nil)
}

func newTraceID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validTraceID(value string) bool {
	if value == "" || len(value) > maxTraceIDBytes {
		return false
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func decodeSignature(value string) ([]byte, bool) {
	prefix := signatureVersion + "."
	if !strings.HasPrefix(value, prefix) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return raw, err == nil && len(raw) == sha256.Size
}

func canonicalMessageID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[0] != '<' || value[len(value)-1] != '>' || strings.ContainsAny(value, "\r\n\t ") {
		return ""
	}
	return value
}

func canonicalRecipient(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 320 || !strings.Contains(value, "@") || strings.ContainsAny(value, "\r\n\t ,") {
		return ""
	}
	return value
}

func singleHeader(header textproto.MIMEHeader, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	return value, value != ""
}

func readHeader(raw []byte) (textproto.MIMEHeader, error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	return reader.ReadMIMEHeader()
}

func automatedHeader(header textproto.MIMEHeader) bool {
	for _, value := range header.Values(HeaderSubmitted) {
		value = strings.TrimSpace(value)
		if value != "" && !strings.EqualFold(value, "no") {
			return true
		}
	}
	return false
}
