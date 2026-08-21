package projection

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	moxmessage "github.com/mjl-/mox/message"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func TestPreviewOfDecodesGB2312(t *testing.T) {
	const want = "外部邮箱中文预览"
	encoded, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(want))
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(strings.Join([]string{
		"From: sender@example.com",
		"To: receiver@mail.imocto.cn",
		"Content-Type: text/plain; charset=GB2312",
		"Content-Transfer-Encoding: base64",
		"",
		base64.StdEncoding.EncodeToString(encoded),
	}, "\r\n"))
	part, err := moxmessage.EnsurePart(nil, false, bytes.NewReader(raw), int64(len(raw)))
	if err != nil && part.Envelope == nil {
		t.Fatal(err)
	}
	if got := previewOf(&part); got != want {
		t.Fatalf("preview = %q, want %q", got, want)
	}
}
