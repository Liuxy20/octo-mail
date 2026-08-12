package webapi

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/rulemetadata"
)

func TestParseEnvelopeExposesSignedRuleAttribution(t *testing.T) {
	authenticator := testRuleMetadataAuthenticator(t)
	metadata := rulemetadata.Metadata{
		OriginalFrom: "customer@example.net",
		SentBy:       "agent@example.com",
		RuleID:       42,
		Hop:          1,
		MessageID:    "<forward@example.com>",
		Recipients:   []string{"owner@example.org"},
		ExpiresAt:    rulemetadata.Expiry(time.Now()),
	}
	signature, err := authenticator.Sign(metadata)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: customer@example.net via Agent Mail <agent@example.com>\r\n" +
		"To: owner@example.org\r\n" +
		"Subject: Original subject\r\n" +
		"Message-ID: " + metadata.MessageID + "\r\n" +
		"X-Octo-Original-From: " + metadata.OriginalFrom + "\r\n" +
		"X-Octo-Sent-By: " + metadata.SentBy + "\r\n" +
		"X-Octo-Rule-ID: 42\r\n" +
		"X-Octo-Rule-Hop: 1\r\n" +
		"X-Octo-Rule-Recipients: owner@example.org\r\n" +
		"X-Octo-Rule-Expires: " + strconv.FormatInt(metadata.ExpiresAt, 10) + "\r\n" +
		"X-Octo-Rule-Signature: " + signature + "\r\n\r\n" +
		"Original body\r\n")

	envelope := parseEnvelope(raw, authenticator, "owner@example.org")
	if envelope.originalFrom != "customer@example.net" {
		t.Fatalf("originalFrom = %q", envelope.originalFrom)
	}
	if envelope.sentBy != "agent@example.com" {
		t.Fatalf("sentBy = %q", envelope.sentBy)
	}
}

func TestParseEnvelopeIgnoresForgedRuleAttribution(t *testing.T) {
	authenticator := testRuleMetadataAuthenticator(t)
	for name, raw := range map[string][]byte{
		"unsigned": []byte("From: agent@example.com\r\n" +
			"To: owner@example.org\r\n" +
			"Message-ID: <external@example.net>\r\n" +
			"X-Octo-Original-From: victim@example.net\r\n" +
			"X-Octo-Sent-By: agent@example.com\r\n" +
			"X-Octo-Rule-ID: 42\r\nX-Octo-Rule-Hop: 3\r\n\r\nBody\r\n"),
		"malformed": []byte("From: agent@example.com\r\n" +
			"To: owner@example.org\r\n" +
			"X-Octo-Original-From: not-an-address\r\n" +
			"X-Octo-Sent-By: also-invalid\r\n\r\nBody\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			envelope := parseEnvelope(raw, authenticator, "owner@example.org")
			if envelope.originalFrom != "" || envelope.sentBy != "" {
				t.Fatalf("untrusted attribution was exposed: %#v", envelope)
			}
		})
	}
}

func testRuleMetadataAuthenticator(t *testing.T) *rulemetadata.Authenticator {
	t.Helper()
	authenticator, err := rulemetadata.New([]byte(strings.Repeat("m", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}
