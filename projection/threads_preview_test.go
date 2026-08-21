package projection

import (
	"bytes"
	"strings"
	"testing"

	moxmessage "github.com/mjl-/mox/message"
)

func TestPreviewOfPrefersHTMLAndDecodesEntities(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@qq.com",
		"To: receiver@mail.imocto.cn",
		"Subject: hello",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"&nbsp; plain fallback",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>&nbsp;修改内容</p>",
		"--body--",
		"",
	}, "\r\n"))
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}

	if got, want := previewOf(&part), "修改内容"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewOfIgnoresHTMLAttachment(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Subject: report",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"REAL BODY: meeting at 3pm",
		"--body",
		`Content-Type: text/html; charset=utf-8; name="report.html"`,
		`Content-Disposition: attachment; filename="report.html"`,
		"",
		"<p>ATTACHMENT INNER TEXT</p>",
		"--body--",
		"",
	}, "\r\n"))
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}

	if got, want := previewOf(&part), "REAL BODY: meeting at 3pm"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewOfFallsBackFromEmptyHTMLAlternative(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Subject: hello",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Important plain text body",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		`<html><body><img src="cid:tracking"></body></html>`,
		"--body--",
		"",
	}, "\r\n"))
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}

	if got, want := previewOf(&part), "Important plain text body"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewOfIgnoresHTMLRawTextAndAttributes(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Subject: hello",
		"Content-Type: text/html; charset=utf-8",
		"",
		`<html><head><style>body{color:red}</style><script>track()</script></head><body><p title="1 < 2">Visible body</p></body></html>`,
	}, "\r\n"))
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}

	if got, want := previewOf(&part), "Visible body"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}
