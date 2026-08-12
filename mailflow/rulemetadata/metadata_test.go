package rulemetadata

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatorSignsCompleteTuple(t *testing.T) {
	authenticator, err := New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata{
		OriginalFrom: "customer@example.net",
		SentBy:       "agent@example.com",
		RuleID:       42,
		Hop:          2,
		MessageID:    "<forward@example.com>",
		Recipients:   []string{"recipient@example.org"},
		ExpiresAt:    Expiry(time.Now()),
	}
	signature, err := authenticator.Sign(metadata)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: agent@example.com\r\n" +
		"Message-ID: " + metadata.MessageID + "\r\n" +
		HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
		HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
		HeaderRuleID + ": 42\r\n" +
		HeaderRuleHop + ": 2\r\n" +
		HeaderRecipients + ": recipient@example.org\r\n" +
		HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n" +
		HeaderSignature + ": " + signature + "\r\n\r\nbody\r\n")
	verified, ok := authenticator.Verify(raw, "recipient@example.org", time.Now())
	if !ok || !reflect.DeepEqual(verified, metadata) {
		t.Fatalf("verified = %#v, %v", verified, ok)
	}

	for name, tampered := range map[string][]byte{
		"attribution": []byte(strings.Replace(string(raw), "customer@example.net", "attacker@example.net", 1)),
		"rule":        []byte(strings.Replace(string(raw), "X-Octo-Rule-ID: 42", "X-Octo-Rule-ID: 43", 1)),
		"hop":         []byte(strings.Replace(string(raw), "X-Octo-Rule-Hop: 2", "X-Octo-Rule-Hop: 3", 1)),
		"message id":  []byte(strings.Replace(string(raw), "<forward@example.com>", "<other@example.com>", 1)),
		"recipient":   []byte(strings.Replace(string(raw), "recipient@example.org", "other@example.org", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := authenticator.Verify(tampered, "recipient@example.org", time.Now()); ok {
				t.Fatal("tampered metadata verified")
			}
		})
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
		Recipients: []string{"recipient@example.org"}, ExpiresAt: Expiry(now),
	}
	signature, err := authenticator.Sign(metadata)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Message-ID: " + metadata.MessageID + "\r\n" +
		HeaderOriginalFrom + ": " + metadata.OriginalFrom + "\r\n" +
		HeaderSentBy + ": " + metadata.SentBy + "\r\n" +
		HeaderRuleID + ": 42\r\n" + HeaderRuleHop + ": 1\r\n" +
		HeaderRecipients + ": recipient@example.org\r\n" +
		HeaderExpires + ": " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n" +
		HeaderSignature + ": " + signature + "\r\n\r\nbody\r\n")
	if _, ok := authenticator.Verify(raw, "other@example.org", now); ok {
		t.Fatal("cross-recipient metadata verified")
	}
	if _, ok := authenticator.Verify(raw, "recipient@example.org", time.Unix(metadata.ExpiresAt+1, 0)); ok {
		t.Fatal("expired metadata verified")
	}
}
