package webapi

import (
	"strings"
	"testing"
)

func TestAttachmentMetadataUsesMIMEPartIDsAndSafeNames(t *testing.T) {
	raw, _, err := compose(composeInput{
		From: "sender@example.com", To: []string{"recipient@example.com"}, Subject: "files", Text: "body",
		Attachments: []attachment{{
			Filename: "../report.txt", ContentType: "text/plain", Content: "aGVsbG8=",
		}},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	attachments, truncated := parseAttachments(raw)
	if truncated || len(attachments) != 1 {
		t.Fatalf("attachments = %v truncated=%v", attachments, truncated)
	}
	got := attachments[0]
	if got.PartID == "" || got.Filename != "report.txt" || got.ContentType != "text/plain" || got.Size != 5 {
		t.Fatalf("attachment metadata = %+v", got)
	}
	if !validPartID(got.PartID) {
		t.Fatalf("invalid generated MIME part id %q", got.PartID)
	}
}

func TestAttachmentHelpersRejectUnsafeInput(t *testing.T) {
	if got := safeAttachmentFilename("../bad\r\nname.txt"); strings.ContainsAny(got, "\r\n/\\") {
		t.Fatalf("unsafe attachment filename = %q", got)
	}
	for _, id := range []string{"", "0", "1..2", "1.-1", "../1", strings.Repeat("1", 129)} {
		if validPartID(id) {
			t.Errorf("validPartID(%q) = true", id)
		}
	}
	attachments, _ := parseAttachments([]byte("Content-Type: multipart/mixed; boundary=missing\r\n\r\nbroken"))
	if attachments == nil {
		t.Fatal("malformed MIME must return a bounded empty list, not nil")
	}
	const configuredLimit = int64(10 << 20)
	if !attachmentDownloadSizeAllowed(configuredLimit, configuredLimit) ||
		attachmentDownloadSizeAllowed(configuredLimit+1, configuredLimit) ||
		attachmentDownloadSizeAllowed(-1, configuredLimit) ||
		attachmentDownloadSizeAllowed(1, 0) {
		t.Fatal("attachment download size boundary is not enforced")
	}
}
