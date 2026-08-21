package mailcontent

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mjl-/mox/message"
)

func parseTestMessage(t *testing.T, lines ...string) message.Part {
	t.Helper()
	raw := []byte(strings.Join(lines, "\r\n"))
	part, err := message.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}
	return part
}

func parseBase64TestMessage(t *testing.T, subtype, body string) message.Part {
	t.Helper()
	lines := []string{
		"From: sender@example.com",
		"To: receiver@example.com",
		"MIME-Version: 1.0",
		"Content-Type: text/" + subtype + "; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	for len(encoded) > 76 {
		lines = append(lines, encoded[:76])
		encoded = encoded[76:]
	}
	lines = append(lines, encoded, "")
	return parseTestMessage(t, lines...)
}

func appendBase64TestPart(lines []string, subtype, body string) []string {
	lines = append(lines,
		"Content-Type: text/"+subtype+"; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
	)
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	for len(encoded) > 76 {
		lines = append(lines, encoded[:76])
		encoded = encoded[76:]
	}
	return append(lines, encoded)
}

func TestPreviewSelectsFirstBodyBranch(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
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
	)

	if got, want := Preview(&part), "MAIN BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewKeepsInlineFilenameBody(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		`Content-Type: text/plain; charset=utf-8; name="body.txt"`,
		`Content-Disposition: inline; filename="body.txt"`,
		"",
		"THE REAL BODY",
	)

	if IsExplicitAttachment(&part) {
		t.Fatal("inline body classified as attachment")
	}
	if got, want := Preview(&part), "THE REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewSkipsMalformedAttachmentDisposition(t *testing.T) {
	for _, disposition := range []string{
		`attachment; filename="=?gb2312?b?ZXZpbC5odG1s?="`,
		`attachment; filename="report.html"; bad=`,
		`attachment (see below); filename="report.html"`,
		`"attachment"; filename="report.html"`,
		`(comment) attachment; filename="report.html"`,
		`=?utf-8?b?YXR0YWNobWVudA==?=; filename="report.html"`,
	} {
		t.Run(disposition, func(t *testing.T) {
			part := parseTestMessage(t,
				"From: sender@example.com",
				"To: receiver@example.com",
				"MIME-Version: 1.0",
				`Content-Type: multipart/mixed; boundary="body"`,
				"",
				"--body",
				"Content-Type: text/html; charset=utf-8",
				"Content-Disposition: "+disposition,
				"",
				"<p>ATTACHMENT CONTENT</p>",
				"--body",
				"Content-Type: text/plain; charset=utf-8",
				"",
				"REAL BODY",
				"--body--",
				"",
			)

			if got, want := Preview(&part), "REAL BODY"; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestPreviewKeepsTopLevelDispositionBody(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Disposition: attachment",
		"",
		"REAL BODY",
	)

	if got, want := Preview(&part), "REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewPrefersLastHTMLAlternative(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"PLAIN BODY",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>FIRST HTML</p>",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>SECOND HTML</p>",
		"--body--",
		"",
	)

	if got, want := Preview(&part), "SECOND HTML"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewUsesLastSupportedAlternative(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>HTML FIRST</p>",
		"--body",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"PLAIN LAST",
		"--body--",
		"",
	)

	if got, want := Preview(&part), "PLAIN LAST"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewAlternativeSelectionDoesNotSpendBudgetOnEarlierParts(t *testing.T) {
	lines := []string{
		"From: sender@example.com",
		"To: receiver@example.com",
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="body"`,
		"",
		"--body",
	}
	lines = appendBase64TestPart(lines, "plain", "PLAIN "+strings.Repeat("p", 40*1024))
	lines = append(lines, "--body")
	lines = appendBase64TestPart(lines, "html", "<p>FIRST HTML "+strings.Repeat("a", 40*1024)+"</p>")
	lines = append(lines,
		"--body",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>SECOND HTML</p>",
		"--body--",
		"",
	)
	part := parseTestMessage(t, lines...)

	if got, want := Preview(&part), "SECOND HTML"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewFindsTextInBoundedHTML(t *testing.T) {
	for name, body := range map[string]string{
		"style":             "<style>" + strings.Repeat("x", 48*1024) + "</style><p>VISIBLE BODY</p>",
		"verification code": "<head><style>p{color:#333}</style></head><body><p>Your verification code is <strong>123456</strong>.</p></body>",
	} {
		t.Run(name, func(t *testing.T) {
			part := parseBase64TestMessage(t, "html", body)
			got := Preview(&part)
			if name == "style" && got != "VISIBLE BODY" {
				t.Fatalf("preview = %q, want %q", got, "VISIBLE BODY")
			}
			if name == "verification code" && got != "Your verification code is 123456." {
				t.Fatalf("preview = %q, want verification code text", got)
			}
		})
	}
}

func TestPreviewIgnoresInvisibleHTMLPreheader(t *testing.T) {
	for name, htmlBody := range map[string]string{
		"visible body after padding":   `<div style="display:none">` + strings.Repeat("&nbsp;&zwnj;", 200) + `</div><p>Your verification code is 123456.</p>`,
		"plain fallback after padding": `<div style="display:none">` + strings.Repeat("&#847;&zwnj;&nbsp;", 200) + `</div>`,
	} {
		t.Run(name, func(t *testing.T) {
			lines := []string{
				"From: sender@example.com",
				"To: receiver@example.com",
				"MIME-Version: 1.0",
				`Content-Type: multipart/alternative; boundary="alternative"`,
				"",
				"--alternative",
			}
			lines = appendBase64TestPart(lines, "plain", "PLAIN FALLBACK")
			lines = append(lines, "--alternative")
			lines = appendBase64TestPart(lines, "html", htmlBody)
			lines = append(lines, "--alternative--", "")
			part := parseTestMessage(t, lines...)

			want := "Your verification code is 123456."
			if name == "plain fallback after padding" {
				want = "PLAIN FALLBACK"
			}
			if got := Preview(&part); got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestHTMLTextPreservesVisibleTextFormatting(t *testing.T) {
	part := parseBase64TestMessage(t, "html", "<p>Cafe\u0301 👩‍💻</p>")
	if got, want := Preview(&part), "Cafe\u0301 👩‍💻"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewHandlesNestedAndImplicitlyClosedIgnoredHTML(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"implicit head close": {`<html><head><title>T</title><body>REAL VISIBLE TEXT</body></html>`, "REAL VISIBLE TEXT"},
		"nested svg":          {`<html><body><svg><svg></svg>HIDDEN SVG TEXT</svg>VISIBLE</body></html>`, "VISIBLE"},
	} {
		t.Run(name, func(t *testing.T) {
			part := parseBase64TestMessage(t, "html", tc.body)
			if got := Preview(&part); got != tc.want {
				t.Fatalf("preview = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPreviewDoesNotTreatIgnoredSourceAsMarkup(t *testing.T) {
	for name, body := range map[string]string{
		"script closing head":   `<head><script>var s = "</head>"; var hidden = 42;</script></head><body><p>REAL BODY</p></body>`,
		"script opening body":   `<head><script>document.write('<body>'); var hidden = 42;</script></head><body><p>REAL BODY</p></body>`,
		"script opening svg":    `<body><script>var icon = "<svg>";</script><p>REAL BODY</p></body>`,
		"script invalid closer": `<body><script>var s = "</script"; var hidden = 42;</script><p>REAL BODY</p></body>`,
		"style markup strings":  `<head><style>.x::before{content:"<svg><body></head>"}</style></head><body><p>REAL BODY</p></body>`,
		"self-closing script":   `<body><script/>HIDDEN SCRIPT TEXT</script><p>REAL BODY</p></body>`,
		"self-closing style":    `<body><style/>HIDDEN STYLE TEXT</style><p>REAL BODY</p></body>`,
	} {
		t.Run(name, func(t *testing.T) {
			part := parseBase64TestMessage(t, "html", body)
			if got, want := Preview(&part), "REAL BODY"; got != want {
				t.Fatalf("preview = %q, want %q", got, want)
			}
		})
	}
}

func TestPreviewFallsBackForLargeHTMLBody(t *testing.T) {
	var html strings.Builder
	html.WriteString("<html><body><p>IMPORTANT FIRST LINE</p>\r\n")
	line := "<div>" + strings.Repeat("x", 512) + "</div>\r\n"
	for html.Len() <= 1024*1024+128*1024 {
		html.WriteString(line)
	}
	html.WriteString("</body></html>")

	tests := map[string]message.Part{
		"HTML only": parseTestMessage(t,
			"From: sender@example.com",
			"To: receiver@example.com",
			"MIME-Version: 1.0",
			"Content-Type: text/html; charset=utf-8",
			"",
			html.String(),
		),
		"related HTML": parseTestMessage(t,
			"From: sender@example.com",
			"To: receiver@example.com",
			"MIME-Version: 1.0",
			`Content-Type: multipart/related; boundary="body"`,
			"",
			"--body",
			"Content-Type: text/html; charset=utf-8",
			"",
			html.String(),
			"--body",
			"Content-Type: image/png",
			"Content-Disposition: inline",
			"",
			"image",
			"--body--",
			"",
		),
		"minified base64 HTML": parseBase64TestMessage(t, "html",
			"<div>IMPORTANT FIRST LINE "+strings.Repeat("x", 1200*1024)+"</div>"),
	}

	for name, part := range tests {
		t.Run(name, func(t *testing.T) {
			got := Preview(&part)
			if !strings.HasPrefix(got, "IMPORTANT FIRST LINE") {
				t.Fatalf("preview = %q, want important first line", got)
			}
		})
	}
}

func TestPreviewKeepsLongDecodedPlainLine(t *testing.T) {
	part := parseBase64TestMessage(t, "plain", "IMPORTANT FIRST LINE "+strings.Repeat("x", 70*1024))
	got := Preview(&part)
	if !strings.HasPrefix(got, "IMPORTANT FIRST LINE") {
		t.Fatalf("preview = %q, want important first line", got)
	}
}

func TestPreviewKeepsExistingQuotedLineSemantics(t *testing.T) {
	part := parseBase64TestMessage(t, "plain", "> "+strings.Repeat("QUOTED TEXT ", 7*1024))
	if got := Preview(&part); !strings.HasPrefix(got, "> QUOTED TEXT") {
		t.Fatalf("preview = %q, want quoted text prefix", got)
	}
}

func TestPreviewKeepsLongVisibleHTMLLine(t *testing.T) {
	for _, size := range []int{70 * 1024, 150 * 1024} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			body := "<style>" + strings.Repeat("x", 20*1024) + "</style><p>VISIBLE " + strings.Repeat("a", size) + "</p>"
			part := parseBase64TestMessage(t, "html", body)
			if got := Preview(&part); !strings.HasPrefix(got, "VISIBLE ") {
				t.Fatalf("preview = %q, want visible text", got)
			}
		})
	}
}

func TestPreviewLargeHTMLAllocationsAreBounded(t *testing.T) {
	body := "<style>" + strings.Repeat("x", 20*1024) + "</style><p>VISIBLE " + strings.Repeat("a", 100*1024) + "</p>"
	part := parseBase64TestMessage(t, "html", body)
	allocs := testing.AllocsPerRun(3, func() {
		if got := Preview(&part); !strings.HasPrefix(got, "VISIBLE ") {
			t.Fatalf("preview = %q, want visible text", got)
		}
	})
	if allocs > 5000 {
		t.Fatalf("Preview allocations = %.0f, want at most 5000", allocs)
	}
}

func TestPreviewTreatsOtherTextSubtypeAsPlain(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"MIME-Version: 1.0",
		"Content-Type: text/calendar; charset=utf-8",
		"",
		"BEGIN:VCALENDAR",
		"SUMMARY:TEAM MEETING",
		"END:VCALENDAR",
	)

	if got, want := Preview(&part), "BEGIN:VCALENDAR SUMMARY:TEAM MEETING END:VCALENDAR"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewDoesNotMutateCharset(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=GB2312",
		"",
		"ASCII BODY",
	)

	if got, want := Preview(&part), "ASCII BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
	if got, want := part.ContentTypeParams["charset"], "GB2312"; got != want {
		t.Fatalf("charset after Preview = %q, want %q", got, want)
	}
}

func TestPreviewTraversalVisitsEachPartOnce(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"REAL BODY",
	)

	const depth = 64
	for range depth {
		part = message.Part{
			MediaType:    "MULTIPART",
			MediaSubType: "ALTERNATIVE",
			Parts:        []message.Part{part},
		}
	}

	traversal := newPreviewTraversal()
	if got, want := traversal.firstBodyPreview(&part, 0, true).text, "REAL BODY"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
	if got, want := traversal.visited, depth+1; got != want {
		t.Fatalf("visited parts = %d, want %d", got, want)
	}
}

func TestPreviewTraversalBoundsDepth(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"TOO DEEP",
	)

	for range maxPreviewMIMEDepth {
		part = message.Part{
			MediaType:    "MULTIPART",
			MediaSubType: "ALTERNATIVE",
			Parts:        []message.Part{part},
		}
	}

	traversal := newPreviewTraversal()
	if got := traversal.firstBodyPreview(&part, 0, true).text; got != "" {
		t.Fatalf("preview = %q, want empty for over-depth MIME tree", got)
	}
	if got, want := traversal.visited, maxPreviewMIMEDepth; got != want {
		t.Fatalf("visited parts = %d, want %d", got, want)
	}
}

func TestPreviewTraversalBoundsPartCount(t *testing.T) {
	parts := make([]message.Part, maxPreviewMIMEParts+10)
	for i := range parts {
		parts[i] = message.Part{MediaType: "APPLICATION", MediaSubType: "OCTET-STREAM"}
	}
	part := message.Part{
		MediaType:    "MULTIPART",
		MediaSubType: "ALTERNATIVE",
		Parts:        parts,
	}

	traversal := newPreviewTraversal()
	if got := traversal.firstBodyPreview(&part, 0, true).text; got != "" {
		t.Fatalf("preview = %q, want empty", got)
	}
	if got, want := traversal.visited, maxPreviewMIMEParts; got != want {
		t.Fatalf("visited parts = %d, want %d", got, want)
	}
}

func TestPreviewTraversalBoundsDecodedBytes(t *testing.T) {
	leaf := parseBase64TestMessage(t, "html", "<style>"+strings.Repeat("x", maxHTMLPreviewDecodedBytes)+"</style>")
	part := message.Part{
		MediaType:    "MULTIPART",
		MediaSubType: "ALTERNATIVE",
		Parts:        []message.Part{leaf, leaf, leaf, leaf},
	}

	traversal := newPreviewTraversal()
	if got := traversal.firstBodyPreview(&part, 0, true).text; got != "" {
		t.Fatalf("preview = %q, want empty", got)
	}
	if got := traversal.remainingDecodedBytes; got != 0 {
		t.Fatalf("remaining decoded bytes = %d, want 0", got)
	}
}

func TestPreviewCleansShortInvalidUTF8(t *testing.T) {
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=x-unknown",
		"",
		"hello \xff world",
	)

	got := Preview(&part)
	if !utf8.ValidString(got) {
		t.Fatalf("preview is not valid UTF-8: %q", got)
	}
	if want := "hello world"; got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}

func TestPreviewCleansLongInvalidUTF8(t *testing.T) {
	body := strings.Repeat("a", 20) + "\xff" + strings.Repeat("b", 200)
	part := parseTestMessage(t,
		"From: sender@example.com",
		"To: receiver@example.com",
		"Content-Type: text/plain; charset=x-unknown",
		"",
		body,
	)

	got := Preview(&part)
	if !utf8.ValidString(got) {
		t.Fatalf("preview is not valid UTF-8: %q", got)
	}
	if len(got) > previewLimit {
		t.Fatalf("preview is %d bytes, want at most %d", len(got), previewLimit)
	}
	want := strings.Repeat("a", 20) + strings.Repeat("b", 120)
	if got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}
