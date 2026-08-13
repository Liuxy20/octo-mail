package outboundpolicy

import (
	"context"
	"testing"
)

func TestKeywordEvaluator(t *testing.T) {
	evaluator := NewKeywordEvaluator([]string{"  Payment ", "合同", "payment"})

	tests := []struct {
		name    string
		intent  Intent
		outcome string
	}{
		{name: "allows unrelated content", intent: Intent{Subject: "Status", Text: "All done"}, outcome: OutcomeAllow},
		{name: "matches body case insensitively", intent: Intent{Subject: "Status", Text: "PAYMENT details"}, outcome: OutcomeOwnerReviewRequired},
		{name: "matches unicode subject substring", intent: Intent{Subject: "合同确认", Text: "请查收"}, outcome: OutcomeOwnerReviewRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), test.intent)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Outcome != test.outcome {
				t.Fatalf("outcome = %q, want %q", decision.Outcome, test.outcome)
			}
			if decision.PolicyVersion == "" {
				t.Fatal("policy version is empty")
			}
		})
	}
}

func TestDigestIsStableAndContentBound(t *testing.T) {
	intent := Intent{Source: SourceOwnerDirect, Operation: "mail.message.send", To: []string{"a@example.net"}, Subject: "Hello", Text: "Body"}
	first := Digest(intent)
	second := Digest(intent)
	if first != second {
		t.Fatal("same intent produced different digests")
	}
	intent.Text = "Changed"
	if first == Digest(intent) {
		t.Fatal("changed intent produced the same digest")
	}
}
