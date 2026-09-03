package junkfilter

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
)

func TestBootstrapDefaultModelWithoutPackage(t *testing.T) {
	mgr := &Manager{SharedEnabled: true}
	imported, info, err := mgr.bootstrapDefaultModel(context.Background(), fstest.MapFS{})
	if err != nil {
		t.Fatal(err)
	}
	if imported || info != (ModelInfo{}) {
		t.Fatalf("model-free bootstrap = %v, %#v; want false, empty info", imported, info)
	}
}

func TestDisabledSharedModelDoesNotBootstrapOrClassify(t *testing.T) {
	mgr := &Manager{SharedEnabled: false}

	imported, info, err := mgr.BootstrapDefaultModel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if imported || info != (ModelInfo{}) {
		t.Fatalf("disabled bootstrap = %v, %#v; want false, empty info", imported, info)
	}

	result, err := mgr.ClassifyGlobalDetailed(context.Background(), []byte("not parsed or queried"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Probability != 0.5 || result.Significant || result.Junk {
		t.Fatalf("disabled classification = %#v; want neutral result", result)
	}
}

func TestGlobalClassificationWithoutUsableFeaturesIsInsignificant(t *testing.T) {
	mgr := NewManager(nil, DefaultParams)
	raw := []byte("From: sender@example.test\r\nX-Filler: " + strings.Repeat("x", 9000) +
		"\r\nSubject: limited offer\r\n\r\nClaim your prize now.\r\n")

	result, err := mgr.ClassifyGlobalDetailed(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Probability != 0.5 || result.Significant || result.Junk {
		t.Fatalf("classification = %#v, want neutral insignificant non-junk result", result)
	}
}

func distinctCJKText(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = rune(0x4e00 + i)
	}
	return string(runes)
}

func foldedCJKSubject(lines, runesPerLine int) string {
	text := []rune(distinctCJKText(lines * runesPerLine))
	var b strings.Builder
	for line := 0; line < lines; line++ {
		if line == 0 {
			b.WriteString("Subject: ")
		} else {
			b.WriteByte(' ')
		}
		start := line * runesPerLine
		b.WriteString(string(text[start : start+runesPerLine]))
		b.WriteString("\r\n")
	}
	return b.String()
}

func TestGlobalCJKFeaturesCannotBeStarvedByIdentityHeaders(t *testing.T) {
	mgr := NewManager(nil, DefaultParams)
	displayName := distinctCJKText(1300)
	raw := []byte("From: " + displayName + " <sender@example.test>\r\n" +
		"To: user@example.test\r\nSubject: 普通通知\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"恭喜中奖，请立即领取现金大奖。\r\n")

	words, badContentType, err := mgr.tokenizeGlobal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if badContentType {
		t.Fatal("valid message reported a bad content type")
	}
	for word := range words {
		for _, prefix := range globalIdentityHeaderPrefixes {
			if strings.HasPrefix(word, prefix) {
				t.Fatalf("global token set retained identity feature %q", word)
			}
		}
	}
	for _, word := range []string{"cjk:恭喜", "cjk:中奖", "cjk:现金", "cjk:大奖"} {
		if _, ok := words[word]; !ok {
			t.Fatalf("global token set is missing body feature %q", word)
		}
	}
}

func TestGlobalCJKFeaturesPrioritizeBodyOverSubject(t *testing.T) {
	mgr := NewManager(nil, DefaultParams)
	raw := []byte("From: sender@example.test\r\nTo: user@example.test\r\n" +
		foldedCJKSubject(40, 60) +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		"恭喜中奖，请立即领取现金大奖。\r\n")

	words, badContentType, err := mgr.tokenizeGlobal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if badContentType {
		t.Fatal("valid folded Subject reported a bad content type")
	}
	for _, word := range []string{"cjk:恭喜", "cjk:中奖", "cjk:现金", "cjk:大奖"} {
		if _, ok := words[word]; !ok {
			t.Fatalf("global token set is missing body feature %q", word)
		}
	}
}

func TestGlobalCJKFeaturesCannotBeStarvedByBodyPadding(t *testing.T) {
	mgr := NewManager(nil, DefaultParams)
	padding := distinctCJKText(1300)
	for name, test := range map[string][2]string{
		"plain text": {
			"text/plain",
			padding + "。恭喜中奖，请立即领取现金大奖。",
		},
		"hidden html": {
			"text/html",
			"<div style=\"display:none\">" + padding + "</div><p>恭喜中奖，请立即领取现金大奖。</p>",
		},
	} {
		t.Run(name, func(t *testing.T) {
			contentType, body := test[0], test[1]
			raw := []byte("From: sender@example.test\r\nTo: user@example.test\r\n" +
				"Subject: 普通通知\r\nContent-Type: " + contentType + "; charset=utf-8\r\n\r\n" + body + "\r\n")
			words, badContentType, err := mgr.tokenizeGlobal(raw)
			if err != nil {
				t.Fatal(err)
			}
			if badContentType {
				t.Fatal("valid message reported a bad content type")
			}
			for _, word := range []string{"cjk:恭喜", "cjk:中奖", "cjk:现金", "cjk:大奖"} {
				if _, ok := words[word]; !ok {
					t.Fatalf("global token set is missing body feature %q", word)
				}
			}
		})
	}
}
