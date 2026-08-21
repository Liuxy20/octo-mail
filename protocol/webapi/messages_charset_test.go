package webapi

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func base64MIMEBody(value string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	var lines []string
	for len(encoded) > 76 {
		lines = append(lines, encoded[:76])
		encoded = encoded[76:]
	}
	return strings.Join(append(lines, encoded), "\r\n")
}

func TestParseBodiesConvertsChineseCharsetsToUTF8(t *testing.T) {
	tests := []struct {
		charset  string
		encoding encoding.Encoding
	}{
		{charset: "GBK", encoding: simplifiedchinese.GBK},
		{charset: "GB18030", encoding: simplifiedchinese.GB18030},
		{charset: "chinese", encoding: simplifiedchinese.GB18030},
		{charset: "csISO58GB231280", encoding: simplifiedchinese.GB18030},
		{charset: "euc-cn", encoding: simplifiedchinese.GB18030},
		{charset: "GB-2312", encoding: simplifiedchinese.GB18030},
		{charset: "GB2312", encoding: simplifiedchinese.GB18030},
		{charset: "GB2312-80", encoding: simplifiedchinese.GB18030},
		{charset: "GB_2312-80", encoding: simplifiedchinese.GB18030},
		{charset: "iso-ir-58", encoding: simplifiedchinese.GB18030},
		{charset: "csGB2312", encoding: simplifiedchinese.GB18030},
		{charset: "x-gbk", encoding: simplifiedchinese.GB18030},
		{charset: "cp936", encoding: simplifiedchinese.GB18030},
	}

	for _, tc := range tests {
		t.Run(tc.charset, func(t *testing.T) {
			const wantText = "修改内容：邮件正文应正常显示中文。"
			const wantHTML = "<p><strong>测试结果：</strong>中文正常。</p>"
			encode := func(value string) string {
				encoded, err := tc.encoding.NewEncoder().String(value)
				if err != nil {
					t.Fatal(err)
				}
				return base64.StdEncoding.EncodeToString([]byte(encoded))
			}
			raw := []byte(strings.Join([]string{
				"From: sender@163.com",
				"To: receiver@mail.imocto.cn",
				"Subject: hello",
				"MIME-Version: 1.0",
				`Content-Type: multipart/alternative; boundary="body"`,
				"",
				"--body",
				fmt.Sprintf("Content-Type: text/plain; charset=%s", tc.charset),
				"Content-Transfer-Encoding: base64",
				"",
				encode(wantText),
				"--body",
				fmt.Sprintf("Content-Type: text/html; charset=%s", tc.charset),
				"Content-Transfer-Encoding: base64",
				"",
				encode(wantHTML),
				"--body--",
				"",
			}, "\r\n"))

			text, html, _ := parseBodies(raw)
			if text != wantText {
				t.Fatalf("text body = %q, want %q", text, wantText)
			}
			if html != wantHTML {
				t.Fatalf("HTML body = %q, want %q", html, wantHTML)
			}
			if got, want := previewText(raw), "测试结果：中文正常。"; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestParseBodiesKeepsInlineFilenameBody(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		`Content-Type: text/plain; charset=utf-8; name="body.txt"`,
		`Content-Disposition: inline; filename="body.txt"`,
		"",
		"THE REAL BODY",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "THE REAL BODY" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
	if got, want := previewText(raw), "THE REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewTextSkipsMalformedAttachmentDisposition(t *testing.T) {
	for _, disposition := range []string{
		`attachment; filename="=?gb2312?b?ZXZpbC5odG1s?="`,
		`attachment; filename="report.html"; bad=`,
	} {
		t.Run(disposition, func(t *testing.T) {
			raw := []byte(strings.Join([]string{
				"From: sender@example.com",
				"To: receiver@mail.imocto.cn",
				"MIME-Version: 1.0",
				`Content-Type: multipart/mixed; boundary="body"`,
				"",
				"--body",
				"Content-Type: text/html; charset=utf-8",
				"Content-Disposition: " + disposition,
				"",
				"<p>ATTACHMENT CONTENT</p>",
				"--body",
				"Content-Type: text/plain; charset=utf-8",
				"",
				"REAL BODY",
				"--body--",
				"",
			}, "\r\n"))

			text, html, _ := parseBodies(raw)
			if text != "REAL BODY" || html != "" {
				t.Fatalf("bodies = text %q, html %q", text, html)
			}
			if got, want := previewText(raw), "REAL BODY"; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestParseBodiesKeepsNonAlternativeHTML(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"PLAIN BODY",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>HTML BODY</p>",
		"--body--",
		"",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "PLAIN BODY" || html != "<p>HTML BODY</p>" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
}

func TestPreviewTextDoesNotUseLaterAlternative(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="outer"`,
		"",
		"--outer",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"MAIN BODY",
		"--outer",
		`Content-Type: multipart/alternative; boundary="alternative"`,
		"",
		"--alternative",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"SECONDARY",
		"--alternative",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>SECONDARY HTML</p>",
		"--alternative--",
		"--outer--",
		"",
	}, "\r\n"))

	if got, want := previewText(raw), "MAIN BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewTextIgnoresHTMLAttachment(t *testing.T) {
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

	if got, want := previewText(raw), "REAL BODY: meeting at 3pm"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
	text, html, _ := parseBodies(raw)
	if text != "REAL BODY: meeting at 3pm" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
}

func TestParseBodiesSkipsLargeHTMLAttachment(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"MIME-Version: 1.0",
		`Content-Type: multipart/mixed; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		`Content-Disposition: attachment; filename="report.html"`,
		"Content-Transfer-Encoding: base64",
		"",
		base64MIMEBody("<p>ATTACHMENT " + strings.Repeat("content ", 20*1024) + "</p>"),
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"THE REAL BODY TEXT",
		"--body--",
		"",
	}, "\r\n"))

	text, htmlBody, _ := parseBodies(raw)
	if got, want := text, "THE REAL BODY TEXT"; got != want {
		t.Fatalf("text body = %q, want %q", got, want)
	}
	if htmlBody != "" {
		t.Fatalf("HTML body = %q, want empty", htmlBody)
	}
}

func TestParseBodiesKeepsTopLevelDispositionBody(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Disposition: attachment",
		"",
		"REAL BODY",
	}, "\r\n"))

	text, html, _ := parseBodies(raw)
	if text != "REAL BODY" || html != "" {
		t.Fatalf("bodies = text %q, html %q", text, html)
	}
	if got, want := previewText(raw), "REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewTextFallsBackFromEmptyHTMLAlternative(t *testing.T) {
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

	if got, want := previewText(raw), "Important plain text body"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewTextTruncatesOnUTF8Boundary(t *testing.T) {
	body := strings.Repeat("中文", 80)
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Subject: hello",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n"))

	got := previewText(raw)
	if !utf8.ValidString(got) {
		t.Fatalf("preview is not valid UTF-8: %q", got)
	}
	if len(got) > 140 {
		t.Fatalf("preview is %d bytes, want at most 140", len(got))
	}
}

func TestPreviewTextPrefersHTMLAndDecodesEntities(t *testing.T) {
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

	if got, want := previewText(raw), "修改内容"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}
