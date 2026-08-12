package autoreplychain

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testRecipient = "bot@octo.test"

var testNow = time.Unix(1_800_000_000, 0)

func TestSignedReplyChain(t *testing.T) {
	chain := mustChain(t, 4)
	source := message("<human@example.net>", nil)

	for count := 1; count <= 4; count++ {
		messageID := "<reply-" + strconv.Itoa(count) + "@octo.test>"
		metadata, context, err := next(chain, source, messageID)
		if err != nil {
			t.Fatalf("Next count %d: %v", count, err)
		}
		if metadata.Count != count {
			t.Fatalf("Next count = %d, want %d", metadata.Count, count)
		}
		if count == 1 && context.Verification != VerificationMissing {
			t.Fatalf("first source verification = %v", context.Verification)
		}
		if chain.IsFinalCount(metadata.Count) != (count == 4) {
			t.Fatalf("IsFinalCount(%d) mismatch", count)
		}
		source = message(messageID, Headers(metadata))
		verified := verify(chain, source)
		if verified.Verification != VerificationValid || verified.Count != count || verified.TraceID != metadata.TraceID {
			t.Fatalf("Verify count %d = %#v", count, verified)
		}
	}

	if _, context, err := next(chain, source, "<reply-5@octo.test>"); !errors.Is(err, ErrLimitReached) || !chain.LimitReached(context) {
		t.Fatalf("fifth reply = context %#v err %v", context, err)
	}
}

func TestTamperedOrReplayedMetadataIsInvalid(t *testing.T) {
	chain := mustChain(t, 4)
	metadata, _, err := next(chain, message("<human@example.net>", nil), "<reply-1@octo.test>")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		raw     []byte
		blocked bool
	}{
		"changed count": {
			raw:     message("<reply-1@octo.test>", merge(Headers(metadata), map[string]string{HeaderCount: "4"})),
			blocked: true,
		},
		"changed trace": {
			raw:     message("<reply-1@octo.test>", merge(Headers(metadata), map[string]string{HeaderTraceID: "attacker"})),
			blocked: true,
		},
		"replayed on another message": {
			raw:     message("<different@octo.test>", Headers(metadata)),
			blocked: true,
		},
		"partial metadata": {
			raw: message("<reply-1@octo.test>", map[string]string{HeaderCount: "4"}),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := verify(chain, tc.raw); got.Verification != VerificationInvalid || got.Count != 0 {
				t.Fatalf("Verify = %#v", got)
			}
			next, _, err := next(chain, tc.raw, "<new@octo.test>")
			if tc.blocked {
				if !errors.Is(err, ErrExternalAutomatedReply) {
					t.Fatalf("Next = %#v, %v", next, err)
				}
				return
			}
			// Invalid metadata without an automated-source marker starts a new
			// trusted chain at one rather than inheriting an attacker count.
			if err != nil || next.Count != 1 {
				t.Fatalf("Next = %#v, %v", next, err)
			}
		})
	}
}

func TestWrongKeyAndFinalPromptState(t *testing.T) {
	chain := mustChain(t, 4)
	other, err := New([]byte(strings.Repeat("z", 32)), 4)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, _ := next(chain, message("<human@example.net>", nil), "<one@octo.test>")
	raw := message("<one@octo.test>", Headers(metadata))
	if got := verify(other, raw); got.Verification != VerificationInvalid {
		t.Fatalf("wrong key verification = %#v", got)
	}

	second, _, _ := next(chain, raw, "<two@octo.test>")
	thirdRaw := message("<two@octo.test>", Headers(second))
	third, _, _ := next(chain, thirdRaw, "<three@octo.test>")
	context := verify(chain, message("<three@octo.test>", Headers(third)))
	if !chain.NextReplyIsFinal(context) {
		t.Fatalf("count 3 should make next reply final: %#v", context)
	}
}

func TestSignedMetadataIsRecipientBoundAndExpires(t *testing.T) {
	chain := mustChain(t, 4)
	metadata, _, err := next(chain, message("<human@example.net>", nil), "<one@octo.test>")
	if err != nil {
		t.Fatal(err)
	}
	raw := message("<one@octo.test>", Headers(metadata))
	if got := chain.Verify(raw, "other@octo.test", testNow); got.Verification != VerificationInvalid {
		t.Fatalf("cross-recipient verification = %#v", got)
	}
	if got := chain.Verify(raw, testRecipient, time.Unix(metadata.ExpiresAt+1, 0)); got.Verification != VerificationInvalid {
		t.Fatalf("expired verification = %#v", got)
	}
}

func TestExternalAutomatedSourceCannotRestartChain(t *testing.T) {
	chain := mustChain(t, 4)
	for name, raw := range map[string][]byte{
		"missing chain": message("<vacation@example.net>", map[string]string{
			HeaderSubmitted: "auto-replied",
		}),
		"invalid chain": message("<ticket@example.net>", map[string]string{
			HeaderSubmitted: "auto-generated",
			HeaderTraceID:   "forged",
			HeaderCount:     "3",
			HeaderSignature: "v1.invalid",
		}),
	} {
		t.Run(name, func(t *testing.T) {
			context := verify(chain, raw)
			if !chain.BlocksAutomaticReply(context) {
				t.Fatalf("source should be blocked: %#v", context)
			}
			if _, gotContext, err := next(chain, raw, "<reply@octo.test>"); !errors.Is(err, ErrExternalAutomatedReply) || !gotContext.Automated {
				t.Fatalf("Next = context %#v err %v", gotContext, err)
			}
		})
	}

	first, _, err := next(chain, message("<human@example.net>", nil), "<one@octo.test>")
	if err != nil {
		t.Fatal(err)
	}
	signed := message("<one@octo.test>", Headers(first))
	context := verify(chain, signed)
	if chain.BlocksAutomaticReply(context) || !context.Automated || context.Verification != VerificationValid {
		t.Fatalf("valid OCTO automated source was blocked: %#v", context)
	}
	second, _, err := next(chain, signed, "<two@octo.test>")
	if err != nil || second.Count != 2 {
		t.Fatalf("valid chain did not continue: %#v, %v", second, err)
	}
}

func TestChainContinuesAcrossInstancesWithSameKey(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	beforeRestart, err := New(key, 4)
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := next(beforeRestart, message("<human@example.net>", nil), "<one@octo.test>")
	if err != nil {
		t.Fatal(err)
	}

	afterRestart, err := New(key, 4)
	if err != nil {
		t.Fatal(err)
	}
	second, context, err := next(afterRestart, message("<one@octo.test>", Headers(first)), "<two@octo.test>")
	if err != nil {
		t.Fatal(err)
	}
	if context.Verification != VerificationValid || context.Count != 1 || second.Count != 2 || second.TraceID != first.TraceID {
		t.Fatalf("chain after restart = context %#v metadata %#v", context, second)
	}
}

func TestAppendFinalNoticeOnce(t *testing.T) {
	got := AppendFinalNotice("结论。\r\n")
	if got != "结论。\n\n"+FinalNotice {
		t.Fatalf("AppendFinalNotice = %q", got)
	}
	if twice := AppendFinalNotice(got); twice != got {
		t.Fatalf("notice appended twice: %q", twice)
	}
}

func TestNewRejectsWeakConfiguration(t *testing.T) {
	if _, err := New([]byte("short"), 4); err == nil {
		t.Fatal("weak key accepted")
	}
	if _, err := New([]byte(strings.Repeat("k", 32)), 0); err == nil {
		t.Fatal("zero maximum accepted")
	}
}

func mustChain(t *testing.T, max int) *Chain {
	t.Helper()
	chain, err := New([]byte(strings.Repeat("k", 32)), max)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func next(chain *Chain, source []byte, messageID string) (Metadata, Context, error) {
	return chain.Next(source, messageID, testRecipient, testRecipient, testNow)
}

func verify(chain *Chain, raw []byte) Context {
	return chain.Verify(raw, testRecipient, testNow)
}

func message(messageID string, headers map[string]string) []byte {
	var b strings.Builder
	b.WriteString("From: sender@example.net\r\nTo: bot@octo.test\r\n")
	b.WriteString("Message-ID: " + messageID + "\r\n")
	for name, value := range headers {
		b.WriteString(name + ": " + value + "\r\n")
	}
	b.WriteString("\r\nbody\r\n")
	return []byte(b.String())
}

func merge(left, right map[string]string) map[string]string {
	out := make(map[string]string, len(left)+len(right))
	for key, value := range left {
		out[key] = value
	}
	for key, value := range right {
		out[key] = value
	}
	return out
}
