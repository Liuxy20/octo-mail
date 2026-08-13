package submit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/mjl-/mox/smtpclient"
)

func TestSMTPResultErrorPreservesValueReply(t *testing.T) {
	cause := smtpclient.Error{
		Permanent: true,
		Code:      550,
		Secode:    "1.1",
		Line:      "550 recipient rejected",
	}
	err := smtpResultErr(fmt.Errorf("deliver: %w", cause), cause)

	var result queue.ResultError
	if !errors.As(err, &result) {
		t.Fatal("wrapped SMTP value did not expose queue.ResultError")
	}
	code, secode := result.SMTPResult()
	if code != 550 || secode != "1.1" {
		t.Fatalf("SMTP result = %d %q, want 550 1.1", code, secode)
	}
	var permanent queue.PermanentError
	if !errors.As(err, &permanent) || !permanent.Permanent() {
		t.Fatal("550 SMTP value was not classified as permanent")
	}
}

func TestSMTPResultErrorPreservesPointerReply(t *testing.T) {
	cause := &smtpclient.Error{
		Code:   550,
		Secode: "1.1",
		Line:   "550 recipient rejected",
	}
	err := smtpResultErr(fmt.Errorf("deliver: %w", cause), cause)

	var result queue.ResultError
	if !errors.As(err, &result) {
		t.Fatal("wrapped SMTP pointer did not expose queue.ResultError")
	}
	var permanent queue.PermanentError
	if !errors.As(err, &permanent) || !permanent.Permanent() {
		t.Fatal("550 SMTP pointer was not classified as permanent")
	}
}

func TestSuppressedRecipientIsTerminalWithCustomerReason(t *testing.T) {
	deliverer := &SMTPDeliverer{
		Suppressed: func(context.Context, int64, string) (bool, error) {
			return true, nil
		},
	}
	err := deliverer.Deliver(context.Background(), queue.Msg{
		AccountID: 1,
		RcptTo:    "blocked@example.com",
	})
	if !errors.Is(err, ErrSuppressed) {
		t.Fatalf("suppressed error = %v, want ErrSuppressed", err)
	}
	var permanent queue.PermanentError
	if !errors.As(err, &permanent) || !permanent.Permanent() {
		t.Fatal("suppressed recipient was not classified as permanent")
	}
	var reason queue.DeliveryReasonError
	if !errors.As(err, &reason) || reason.DeliveryReasonCode() != "recipient_suppressed" {
		t.Fatalf("suppressed reason = %v, want recipient_suppressed", reason)
	}
}
