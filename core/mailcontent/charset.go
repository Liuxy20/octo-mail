// Package mailcontent provides shared MIME text decoding helpers.
package mailcontent

import (
	"io"
	"strings"

	"github.com/mjl-/mox/message"
)

// ReaderUTF8 returns a transfer-decoded text reader converted from the declared
// MIME charset to UTF-8. Common Chinese aliases are decoded as GB18030, which is
// a superset of GB2312 and GBK.
func ReaderUTF8(part *message.Part) io.Reader {
	charset := normalizedCharset(part.ContentTypeParams["charset"])
	return message.DecodeReader(charset, part.Reader())
}

// ReadUTF8 reads a MIME text part and removes any undecodable byte sequences so
// the result is safe for JSON and PostgreSQL text values.
func ReadUTF8(part *message.Part) string {
	b, _ := io.ReadAll(ReaderUTF8(part))
	return strings.ToValidUTF8(string(b), "")
}

func normalizedCharset(charset string) string {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "chinese", "cp936", "csgb2312", "csiso58gb231280", "euc-cn",
		"gb-2312", "gb2312", "gb2312-80", "gb_2312-80", "iso-ir-58", "x-gbk":
		return "gb18030"
	}
	return charset
}
