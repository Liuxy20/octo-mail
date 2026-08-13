package projection

import (
	"bytes"
	"encoding/base64"
	"mime"
	"mime/quotedprintable"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestExtractSearchTextDecodesMIME(t *testing.T) {
	subject := mime.BEncoding.Encode("UTF-8", "班级通知")
	body := "各位同学们，下午好"

	t.Run("base64", func(t *testing.T) {
		raw := []byte("Subject: " + subject + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(body)) + "\r\n")
		got := extractSearchText(raw)
		if !strings.Contains(got, "班级通知") || !strings.Contains(got, "同学们") {
			t.Fatalf("decoded search text = %q", got)
		}
	})

	t.Run("quoted-printable", func(t *testing.T) {
		var encoded bytes.Buffer
		writer := quotedprintable.NewWriter(&encoded)
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		raw := []byte("Subject: " + subject + "\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + encoded.String())
		got := extractSearchText(raw)
		if !strings.Contains(got, "班级通知") || !strings.Contains(got, "同学们") {
			t.Fatalf("decoded search text = %q", got)
		}
	})
}

func TestExtractSearchTextPreservesHeadersAttachmentsAndCharsets(t *testing.T) {
	body := "各位同学们下午好"
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: notice\r\n" +
		"From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@example.net>\r\n" +
		"Message-ID: <uniqueid-12345@example.com>\r\n" +
		"Reply-To: billing@example.org\r\n" +
		"List-Id: acme-announce.example\r\n" +
		"X-Custom-Tracker: TRACKTOKEN9\r\n" +
		"Content-Type: multipart/mixed; boundary=bnd\r\n\r\n" +
		"--bnd\r\nContent-Type: text/plain; charset=gbk\r\n\r\n")
	raw = append(raw, gbk...)
	raw = append(raw, []byte("\r\n--bnd\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=invoice-2024.pdf\r\n\r\npdf\r\n--bnd--\r\n")...)

	got := extractSearchText(raw)
	for _, want := range []string{
		"同学们", "uniqueid-12345", "billing@example.org",
		"acme-announce", "TRACKTOKEN9", "invoice-2024.pdf",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("search text missing %q: %q", want, got)
		}
	}
}

func TestExtractSearchTextFallsBackForMalformedMultipart(t *testing.T) {
	raw := []byte("Subject: hello\r\nContent-Type: multipart/mixed; boundary=bnd\r\n\r\n" +
		"--bnd\r\nContent-Type: text/plain\r\n\r\nSECRETBODYTOKEN\r\n")
	got := extractSearchText(raw)
	if !strings.Contains(got, "SECRETBODYTOKEN") {
		t.Fatalf("malformed multipart search text = %q", got)
	}
	if count := strings.Count(got, "Subject: hello"); count != 1 {
		t.Fatalf("malformed multipart indexed header %d times: %q", count, got)
	}
}

func TestExtractSearchTextBoundsMalformedRawBodyBeforeSanitizing(t *testing.T) {
	raw := []byte("Subject: bounded\r\nContent-Type: multipart/mixed; boundary=missing\r\n\r\nSEARCHABLE\r\n")
	raw = append(raw, bytes.Repeat([]byte{0xff}, 8<<20)...)

	got := extractSearchText(raw)
	if !strings.Contains(got, "SEARCHABLE") {
		t.Fatalf("bounded malformed body lost searchable text")
	}
	if len(got) > maxSearchTextBytes {
		t.Fatalf("search text size = %d, want <= %d", len(got), maxSearchTextBytes)
	}
}

func TestExtractSearchTextRemovesNUL(t *testing.T) {
	got := extractSearchText([]byte("Subject: safe\x00subject\r\n\r\nbody\x00text"))
	if strings.ContainsRune(got, '\x00') {
		t.Fatalf("search text contains PostgreSQL-invalid NUL: %q", got)
	}
}
