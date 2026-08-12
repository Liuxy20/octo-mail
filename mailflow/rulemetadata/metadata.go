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
	"errors"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	HeaderOriginalFrom = "X-Octo-Original-From"
	HeaderSentBy       = "X-Octo-Sent-By"
	HeaderRuleID       = "X-Octo-Rule-ID"
	HeaderRuleHop      = "X-Octo-Rule-Hop"
	HeaderSignature    = "X-Octo-Rule-Signature"

	signatureVersion = "v1"
	minKeyBytes      = 32
	maxAddressBytes  = 320
	maxHop           = 1_000_000
)

// Metadata is the complete server-owned rule-forwarding tuple. MessageID binds
// the signature to the concrete generated message rather than just a rule.
type Metadata struct {
	OriginalFrom string
	SentBy       string
	RuleID       int64
	Hop          int
	MessageID    string
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

func (a *Authenticator) Sign(metadata Metadata) (string, error) {
	metadata, err := canonicalMetadata(metadata)
	if err != nil {
		return "", err
	}
	return signatureVersion + "." + base64.RawURLEncoding.EncodeToString(a.mac(metadata)), nil
}

// Verify checks a raw RFC 5322 message. Missing, partial, duplicated, malformed,
// or tampered metadata is rejected as one unit.
func (a *Authenticator) Verify(raw []byte) (Metadata, bool) {
	header, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	if err != nil {
		return Metadata{}, false
	}
	return a.VerifyHeader(header)
}

func (a *Authenticator) VerifyHeader(header textproto.MIMEHeader) (Metadata, bool) {
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
	metadata, err := canonicalMetadata(Metadata{
		OriginalFrom: originalFrom,
		SentBy:       sentBy,
		RuleID:       ruleID,
		Hop:          hop,
		MessageID:    messageID,
	})
	if err != nil {
		return Metadata{}, false
	}
	signature, ok := decodeSignature(signatureText)
	if !ok || !hmac.Equal(signature, a.mac(metadata)) {
		return Metadata{}, false
	}
	return metadata, true
}

func (a *Authenticator) mac(metadata Metadata) []byte {
	mac := hmac.New(sha256.New, a.key)
	fmt.Fprintf(mac, "%s\n%s\n%s\n%d\n%d\n%s",
		signatureVersion, metadata.OriginalFrom, metadata.SentBy,
		metadata.RuleID, metadata.Hop, metadata.MessageID)
	return mac.Sum(nil)
}

func canonicalMetadata(metadata Metadata) (Metadata, error) {
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
	return metadata, nil
}

func singleHeader(header textproto.MIMEHeader, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	return value, value != ""
}

func decodeSignature(value string) ([]byte, bool) {
	prefix := signatureVersion + "."
	if !strings.HasPrefix(value, prefix) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return raw, err == nil && len(raw) == sha256.Size
}

func validMessageID(value string) bool {
	return len(value) >= 3 && value[0] == '<' && value[len(value)-1] == '>' &&
		!strings.ContainsAny(value, "\r\n\t ")
}
