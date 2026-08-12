package rulemetadata

import (
	"strings"
	"testing"
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
		HeaderSignature + ": " + signature + "\r\n\r\nbody\r\n")
	verified, ok := authenticator.Verify(raw)
	if !ok || verified != metadata {
		t.Fatalf("verified = %#v, %v", verified, ok)
	}

	for name, tampered := range map[string][]byte{
		"attribution": []byte(strings.Replace(string(raw), "customer@example.net", "attacker@example.net", 1)),
		"rule":        []byte(strings.Replace(string(raw), "X-Octo-Rule-ID: 42", "X-Octo-Rule-ID: 43", 1)),
		"hop":         []byte(strings.Replace(string(raw), "X-Octo-Rule-Hop: 2", "X-Octo-Rule-Hop: 3", 1)),
		"message id":  []byte(strings.Replace(string(raw), "<forward@example.com>", "<other@example.com>", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := authenticator.Verify(tampered); ok {
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
		if _, ok := authenticator.Verify(raw); ok {
			t.Fatal("partial external metadata verified")
		}
	}
}
