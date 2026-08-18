package rulemetadata

import (
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatorAcceptsLegacySingleRuleMetadataForAttributionOnly(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	metadata, err := canonicalBaseMetadata(Metadata{
		OriginalFrom: "customer@example.net", SentBy: "agent@example.com",
		RuleID: 42, Hop: 2, MessageID: "<legacy@example.com>",
		Recipients: []string{"recipient@example.org"}, ExpiresAt: Expiry(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := legacySignatureVersion + "." + base64.RawURLEncoding.EncodeToString(authenticator.mac(metadata, legacySignatureVersion, [sha256.Size]byte{}))
	raw := []byte("Message-ID: " + metadata.MessageID + "\r\n" +
		HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
		HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
		HeaderRuleID + ": 42\r\n" + HeaderRuleHop + ": 2\r\n" +
		HeaderRecipients + ": recipient@example.org\r\n" +
		HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n" +
		HeaderSignature + ": " + signature + "\r\n\r\nbody\r\n")
	verified, ok := authenticator.Verify(raw, "recipient@example.org", now)
	if !ok || !reflect.DeepEqual(verified.RuleTrace, []int64{42}) {
		t.Fatalf("legacy verified = %#v, %v", verified, ok)
	}
	if verified.ChainTrusted {
		t.Fatal("legacy metadata was allowed to continue a rule chain")
	}
}

func TestVerificationContentDigestRequiresRuleSignature(t *testing.T) {
	raw := []byte("From: sender@example.net\r\nTo: agent@example.org\r\nSubject: ordinary\r\n\r\n" + strings.Repeat("body", 1024))
	if _, _, ok := verificationContentDigest(raw); ok {
		t.Fatal("verificationContentDigest accepted an unsigned message")
	}
	if _, _, ok := messageContentDigest(raw); !ok {
		t.Fatal("messageContentDigest rejected unsigned content needed for signing")
	}
}

func TestAuthenticatorBindsForwardContentAndRouting(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{
		OriginalFrom: "customer@example.net",
		SentBy:       "agent@example.com",
		RuleID:       42,
		Hop:          2,
		RuleTrace:    []int64{7, 42},
		MessageID:    "<forward@example.com>",
		Recipients:   []string{"recipient@example.org"},
		ExpiresAt:    Expiry(time.Now()),
	}
	raw := signedTestMessage(t, authenticator, metadata,
		"From: agent@example.com\r\n"+
			"Reply-To: replies@example.com\r\n"+
			"To: recipient@example.org\r\n"+
			"Subject: Original subject\r\n"+
			"Date: Tue, 18 Aug 2026 12:00:00 +0800\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: multipart/mixed; boundary=test\r\n",
		"--test\r\nContent-Type: text/plain\r\n\r\nOriginal body\r\n"+
			"--test\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.txt\r\n\r\nattachment bytes\r\n--test--\r\n")
	verified, ok := authenticator.Verify(raw, "recipient@example.org", time.Now())
	want := metadata
	want.ChainTrusted = true
	if !ok || !reflect.DeepEqual(verified, want) {
		t.Fatalf("verified = %#v, %v", verified, ok)
	}

	for name, replacements := range map[string][2]string{
		"attribution": {"customer@example.net", "attacker@example.net"},
		"rule":        {"X-Octo-Rule-ID: 42", "X-Octo-Rule-ID: 43"},
		"hop":         {"X-Octo-Rule-Hop: 2", "X-Octo-Rule-Hop: 3"},
		"trace":       {"X-Octo-Rule-Trace: 7,42", "X-Octo-Rule-Trace: 8,42"},
		"message id":  {"<forward@example.com>", "<other@example.com>"},
		"recipient":   {"recipient@example.org", "other@example.org"},
		"from":        {"From: agent@example.com", "From: attacker@example.net"},
		"reply-to":    {"Reply-To: replies@example.com", "Reply-To: attacker@example.net"},
		"to":          {"To: recipient@example.org", "To: attacker@example.net"},
		"subject":     {"Subject: Original subject", "Subject: Modified subject"},
		"body":        {"Original body", "Modified body"},
		"attachment":  {"attachment bytes", "modified bytes"},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := []byte(strings.Replace(string(raw), replacements[0], replacements[1], 1))
			if _, ok := authenticator.Verify(tampered, "recipient@example.org", time.Now()); ok {
				t.Fatal("tampered message verified")
			}
		})
	}

	// Relays may prepend transport-only headers after the server signs the
	// message. Those headers must not invalidate the content-bound signature.
	withReceived := append([]byte("Received: from relay.example\r\n"), raw...)
	if _, ok := authenticator.Verify(withReceived, "recipient@example.org", time.Now()); !ok {
		t.Fatal("transport-added Received header invalidated the signature")
	}
}

func TestAuthenticatorAcceptsAnyOwnedRecipient(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{
		OriginalFrom: "customer@example.net", SentBy: "agent@example.com",
		RuleID: 42, Hop: 1, RuleTrace: []int64{42}, MessageID: "<alias@example.com>",
		Recipients: []string{"alias@example.org"}, ExpiresAt: Expiry(time.Now()),
	}
	raw := signedTestMessage(t, authenticator, metadata,
		"From: agent@example.com\r\nTo: alias@example.org\r\n", "body\r\n")
	if _, ok := authenticator.VerifyAny(raw, []string{"primary@example.org", "alias@example.org"}, time.Now()); !ok {
		t.Fatal("signed alias recipient was not accepted")
	}
	if _, ok := authenticator.VerifyAny(raw, []string{"primary@example.org"}, time.Now()); ok {
		t.Fatal("message trusted for an unrelated account address")
	}
}

func TestAuthenticatorRejectsPartialAndDuplicateMetadata(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte("Message-ID: <external@example.net>\r\nX-Octo-Rule-Hop: 3\r\n\r\n"),
		[]byte("Message-ID: <external@example.net>\r\nX-Octo-Original-From: attacker@example.net\r\nX-Octo-Sent-By: agent@example.com\r\n\r\n"),
	} {
		if _, ok := authenticator.Verify(raw, "recipient@example.org", time.Now()); ok {
			t.Fatal("partial external metadata verified")
		}
	}
}

func TestAuthenticatorRejectsCrossRecipientAndExpiredMetadata(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	metadata := Metadata{
		OriginalFrom: "customer@example.net", SentBy: "agent@example.com",
		RuleID: 42, Hop: 1, MessageID: "<forward@example.com>",
		RuleTrace:  []int64{42},
		Recipients: []string{"recipient@example.org"}, ExpiresAt: Expiry(now),
	}
	raw := signedTestMessage(t, authenticator, metadata,
		"From: agent@example.com\r\nTo: recipient@example.org\r\n", "body\r\n")
	if _, ok := authenticator.Verify(raw, "other@example.org", now); ok {
		t.Fatal("cross-recipient metadata verified")
	}
	if _, ok := authenticator.Verify(raw, "recipient@example.org", time.Unix(metadata.ExpiresAt+1, 0)); ok {
		t.Fatal("expired metadata verified")
	}
}

func TestParseRuleTraceRejectsMalformedValues(t *testing.T) {
	for _, value := range []string{"", "1,", ",1", "1,,2", "1,1", "0", "-1"} {
		if _, err := parseRuleTrace(value); err == nil {
			t.Fatalf("parseRuleTrace(%q) succeeded", value)
		}
	}
	if _, err := parseRuleTrace(strings.Repeat(",", maxHop)); err == nil {
		t.Fatal("oversized rule trace succeeded")
	}
}

func TestAuthenticatorVerifiesListsBeforeParsingThem(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	metadata := Metadata{
		OriginalFrom: "customer@example.net", SentBy: "agent@example.com",
		RuleID: 2, Hop: 3, MessageID: "<forward@example.com>", ExpiresAt: Expiry(now),
	}
	unsigned := func(trace, recipients string) []byte {
		return []byte("From: agent@example.com\r\n" +
			"To: recipient@example.org\r\n" +
			"Message-ID: " + metadata.MessageID + "\r\n" +
			HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
			HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
			HeaderRuleID + ": 2\r\n" + HeaderRuleHop + ": 3\r\n" +
			HeaderRuleTrace + ": " + trace + "\r\n" +
			HeaderRecipients + ": " + recipients + "\r\n" +
			HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n\r\nbody\r\n")
	}
	withSignature := func(raw []byte, signature string) []byte {
		boundary := strings.Index(string(raw), "\r\n\r\n")
		if boundary < 0 {
			t.Fatal("test message missing header boundary")
		}
		return []byte(string(raw[:boundary+2]) + HeaderSignature + ": " + signature + "\r\n" + string(raw[boundary+2:]))
	}

	// An invalid MAC must fail without parsing a large attacker-controlled trace.
	largeTrace := strings.Repeat("1,", 100_000) + "1"
	invalidMAC := signatureVersion + "." + base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	if _, ok := authenticator.Verify(withSignature(unsigned(largeTrace, "recipient@example.org"), invalidMAC), "recipient@example.org", now); ok {
		t.Fatal("invalid signature with a large trace verified")
	}

	// Once the MAC is valid, malformed list syntax must still fail closed.
	malformedTrace := "1,,2"
	raw := unsigned(malformedTrace, "recipient@example.org")
	_, digest, ok := messageContentDigest(raw)
	if !ok {
		t.Fatal("could not digest test message")
	}
	signature := signatureVersion + "." + base64.RawURLEncoding.EncodeToString(
		authenticator.macFields(metadata, signatureVersion, malformedTrace, "recipient@example.org", digest),
	)
	if _, ok := authenticator.Verify(withSignature(raw, signature), "recipient@example.org", now); ok {
		t.Fatal("valid signature authorized a malformed trace")
	}
}

func signedTestMessage(t *testing.T, authenticator *Authenticator, metadata Metadata, messageHeaders, body string) []byte {
	t.Helper()
	trace, err := FormatRuleTrace(metadata.RuleTrace)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := CanonicalRecipients(metadata.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(messageHeaders +
		"Message-ID: " + metadata.MessageID + "\r\n" +
		HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
		HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
		HeaderRuleID + ": " + strconv.FormatInt(metadata.RuleID, 10) + "\r\n" +
		HeaderRuleHop + ": " + strconv.Itoa(metadata.Hop) + "\r\n" +
		HeaderRuleTrace + ": " + trace + "\r\n" +
		HeaderRecipients + ": " + recipients + "\r\n" +
		HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n\r\n" + body)
	signature, err := authenticator.Sign(metadata, raw)
	if err != nil {
		t.Fatal(err)
	}
	boundary := strings.Index(string(raw), "\r\n\r\n")
	if boundary < 0 {
		t.Fatal("test message missing header boundary")
	}
	signed := make([]byte, 0, len(raw)+len(signature)+len(HeaderSignature)+4)
	signed = append(signed, raw[:boundary+2]...)
	signed = append(signed, HeaderSignature+": "+signature+"\r\n"...)
	signed = append(signed, raw[boundary+2:]...)
	return signed
}
