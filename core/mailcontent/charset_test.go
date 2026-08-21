package mailcontent

import "testing"

func TestNormalizedCharsetChineseAliases(t *testing.T) {
	for _, charset := range []string{
		"chinese", "CP936", "csGB2312", "csISO58GB231280", "euc-cn",
		"GB-2312", "GB2312", "GB2312-80", "GB_2312-80", "iso-ir-58", "x-gbk",
	} {
		if got, want := normalizedCharset(charset), "gb18030"; got != want {
			t.Fatalf("normalizedCharset(%q) = %q, want %q", charset, got, want)
		}
	}
	if got, want := normalizedCharset("windows-1252"), "windows-1252"; got != want {
		t.Fatalf("normalizedCharset(windows-1252) = %q, want %q", got, want)
	}
}
