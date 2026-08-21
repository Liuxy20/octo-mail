// Package mailcontent provides shared MIME body decoding and preview helpers.
package mailcontent

import (
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mjl-/mox/message"
	"golang.org/x/net/html"
)

const (
	previewLimit                 = 140
	maxHTMLPreviewDecodedBytes   = 128 * 1024
	maxHTMLPreviewExtractedBytes = 4 * 1024
	maxPlainPreviewDecodedBytes  = 32 * 1024
	maxPreviewDecodedBytes       = 512 * 1024
	maxPreviewMIMEDepth          = 100
	maxPreviewMIMEParts          = 10000
)

// ReaderUTF8 returns a transfer-decoded text reader converted to UTF-8. Common
// Chinese aliases that x/text does not resolve are decoded as GB18030, which is
// a superset of GB2312 and GBK.
func ReaderUTF8(part *message.Part) io.Reader {
	charset := normalizedCharset(part.ContentTypeParams["charset"])
	return message.DecodeReader(charset, part.Reader())
}

func normalizedCharset(charset string) string {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "chinese", "cp936", "csgb2312", "csiso58gb231280", "euc-cn",
		"gb-2312", "gb2312", "gb2312-80", "gb_2312-80", "iso-ir-58", "x-gbk":
		return "gb18030"
	}
	return charset
}

// IsExplicitAttachment reports whether a MIME part declares an attachment
// disposition. A filename alone does not make an inline body an attachment.
// When parameters are malformed, the disposition token is still honored.
func IsExplicitAttachment(part *message.Part) bool {
	if part.ContentDisposition == nil {
		return false
	}
	raw := strings.TrimSpace(*part.ContentDisposition)
	if raw == "" {
		return false
	}
	disposition, _, _ := part.DispositionFilename()
	if strings.EqualFold(disposition, "attachment") {
		return true
	}
	if i := strings.IndexByte(raw, ';'); i >= 0 {
		raw = raw[:i]
	}
	if decoded, err := new(mime.WordDecoder).DecodeHeader(raw); err == nil {
		raw = decoded
	}
	raw = trimLeadingComments(raw)
	if i := strings.IndexAny(raw, " \t\r\n("); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	return strings.EqualFold(raw, "attachment")
}

func trimLeadingComments(s string) string {
	for {
		s = strings.TrimSpace(s)
		if !strings.HasPrefix(s, "(") {
			return s
		}
		depth := 0
		escaped := false
		closed := false
		for i, r := range s {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			switch r {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					s = s[i+1:]
					closed = true
				}
			}
			if closed {
				break
			}
		}
		if !closed {
			return s
		}
	}
}

// Preview returns a whitespace-normalized, UTF-8-safe message preview.
// Multipart alternatives are tried from most to least faithful per RFC 2046,
// and decoded leaf content is read through bounded text extractors.
func Preview(part *message.Part) string {
	traversal := newPreviewTraversal()
	s := traversal.firstBodyPreview(part, 0, true).text
	s = validUTF8(s)
	s = strings.Join(strings.Fields(s), " ")
	return truncateUTF8(s, previewLimit)
}

// truncateUTF8 limits s to maxBytes without splitting a UTF-8 sequence.
func truncateUTF8(s string, maxBytes int) string {
	s = validUTF8(s)
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func validUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}

type bodyPreview struct {
	text string
}

type previewTraversal struct {
	visited               int
	remainingDecodedBytes int64
}

func newPreviewTraversal() previewTraversal {
	return previewTraversal{remainingDecodedBytes: maxPreviewDecodedBytes}
}

func (t *previewTraversal) boundedPlainPreview(part *message.Part, partLimit int64) string {
	limit := min(partLimit, t.remainingDecodedBytes)
	if limit <= 0 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(ReaderUTF8(part), limit))
	t.remainingDecodedBytes -= int64(len(body))
	if err != nil || len(body) == 0 {
		return ""
	}
	return string(body)
}

func (t *previewTraversal) leafPreview(part *message.Part) bodyPreview {
	mediaType := strings.ToUpper(part.MediaType + "/" + part.MediaSubType)
	var s string
	if mediaType == "TEXT/HTML" {
		limit := min(int64(maxHTMLPreviewDecodedBytes), t.remainingDecodedBytes)
		var read int64
		s, read = htmlText(ReaderUTF8(part), limit, maxHTMLPreviewExtractedBytes)
		t.remainingDecodedBytes -= read
	} else if strings.EqualFold(part.MediaType, "TEXT") || part.MediaType == "" {
		s = t.boundedPlainPreview(part, maxPlainPreviewDecodedBytes)
	}
	if strings.TrimSpace(s) == "" {
		return bodyPreview{}
	}
	return bodyPreview{text: s}
}

var ignoredHTMLPreviewElements = map[string]bool{
	"dialog": true, "head": true, "map": true, "math": true,
	"script": true, "style": true, "svg": true, "template": true,
}

var blockHTMLPreviewElements = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"br": true, "dd": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true,
	"form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hr": true, "li": true,
	"main": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "tbody": true, "td": true,
	"tfoot": true, "th": true, "thead": true, "tr": true, "ul": true,
}

type htmlTextWriter struct {
	b              strings.Builder
	limit          int
	pending        byte
	hasVisibleBase bool
	full           bool
}

func (w *htmlTextWriter) separator(line bool) {
	if w.b.Len() == 0 {
		return
	}
	if line || w.pending == 0 {
		w.pending = '\n'
	}
}

func (w *htmlTextWriter) write(data []byte) {
	for len(data) > 0 && !w.full {
		r, size := utf8.DecodeRune(data)
		data = data[size:]
		if !w.hasVisibleBase && (unicode.Is(unicode.Cf, r) || r == '\u034f') {
			continue
		}
		if unicode.IsSpace(r) {
			if w.b.Len() > 0 && w.pending == 0 {
				w.pending = ' '
			}
			continue
		}
		needed := utf8.RuneLen(r)
		if w.pending != 0 && w.b.Len() > 0 {
			needed++
		}
		if w.b.Len()+needed > w.limit {
			w.full = true
			return
		}
		if w.pending != 0 && w.b.Len() > 0 {
			w.b.WriteByte(w.pending)
			w.pending = 0
		}
		w.b.WriteRune(r)
		if !unicode.Is(unicode.Mn, r) {
			w.hasVisibleBase = true
		}
	}
}

func htmlText(r io.Reader, inputLimit int64, outputLimit int) (string, int64) {
	if inputLimit <= 0 || outputLimit <= 0 {
		return "", 0
	}
	lr := &io.LimitedReader{R: r, N: inputLimit}
	z := html.NewTokenizer(lr)
	z.SetMaxBuf(int(inputLimit))
	w := htmlTextWriter{limit: outputLimit}
	var ignored []string
	for !w.full {
		switch z.Next() {
		case html.ErrorToken:
			return strings.TrimSpace(w.b.String()), inputLimit - lr.N
		case html.TextToken:
			if len(ignored) == 0 {
				w.write(z.Text())
			}
		case html.StartTagToken:
			name, _ := z.TagName()
			tag := string(name)
			// The tokenizer does not apply HTML5's implicit </head> rule.
			// Recover it here so a missing end tag does not hide the body.
			if tag == "body" && len(ignored) == 1 && ignored[0] == "head" {
				ignored = nil
			}
			if ignoredHTMLPreviewElements[tag] {
				ignored = append(ignored, tag)
			} else if len(ignored) == 0 && blockHTMLPreviewElements[tag] {
				w.separator(true)
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if len(ignored) > 0 && ignored[len(ignored)-1] == tag {
				ignored = ignored[:len(ignored)-1]
			} else if len(ignored) == 0 && blockHTMLPreviewElements[tag] {
				w.separator(true)
			}
		case html.SelfClosingTagToken:
			name, _ := z.TagName()
			if len(ignored) == 0 && blockHTMLPreviewElements[string(name)] {
				w.separator(true)
			}
		}
	}
	return strings.TrimSpace(w.b.String()), inputLimit - lr.N
}

func (t *previewTraversal) firstBodyPreview(part *message.Part, depth int, root bool) bodyPreview {
	if part == nil || depth >= maxPreviewMIMEDepth || t.visited >= maxPreviewMIMEParts {
		return bodyPreview{}
	}
	t.visited++
	if !root && IsExplicitAttachment(part) {
		return bodyPreview{}
	}

	mediaType := strings.ToUpper(part.MediaType + "/" + part.MediaSubType)
	if len(part.Parts) == 0 {
		return t.leafPreview(part)
	}
	if mediaType == "MULTIPART/ENCRYPTED" {
		return bodyPreview{}
	}

	limit := len(part.Parts)
	if mediaType == "MULTIPART/SIGNED" && limit > 1 {
		limit = 1
	}
	if depth+1 >= maxPreviewMIMEDepth {
		return bodyPreview{}
	}

	if mediaType == "MULTIPART/ALTERNATIVE" {
		// RFC 2046 section 5.1.4 orders alternatives by increasing
		// faithfulness. Try supported alternatives from last to first, falling
		// back only when a later representation has no meaningful preview.
		for i := limit - 1; i >= 0 && t.visited < maxPreviewMIMEParts; i-- {
			candidate := t.firstBodyPreview(&part.Parts[i], depth+1, false)
			if candidate.text != "" {
				return candidate
			}
		}
		return bodyPreview{}
	}

	for i := 0; i < limit && t.visited < maxPreviewMIMEParts; i++ {
		if candidate := t.firstBodyPreview(&part.Parts[i], depth+1, false); candidate.text != "" {
			return candidate
		}
	}
	return bodyPreview{}
}
