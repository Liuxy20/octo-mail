package webapi

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/simplifiedchinese"
)

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
				"From: sender@example.com",
				"To: receiver@mail.imocto.cn",
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
			if got, want := previewText(raw), wantText; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestParseBodiesDecodesQuotedPrintableGB2312(t *testing.T) {
	const want = "验证码：123456"
	encoded, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(want))
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := quotedprintable.NewWriter(&body)
	if _, err := writer.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Content-Type: text/plain; charset=GB2312",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		body.String(),
	}, "\r\n"))

	text, _, _ := parseBodies(raw)
	if text != want {
		t.Fatalf("text body = %q, want %q", text, want)
	}
}

func TestPreviewTextTruncatesDecodedUTF8Safely(t *testing.T) {
	body := strings.Repeat("中", 200)
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n"))

	preview := previewText(raw)
	if !utf8.ValidString(preview) {
		t.Fatalf("preview is invalid UTF-8: %q", preview)
	}
	if len(preview) > 140 {
		t.Fatalf("preview is %d bytes, want at most 140", len(preview))
	}
}
