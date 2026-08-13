package blob

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeS3PrefixPath(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty keeps legacy layout", raw: "", want: ""},
		{name: "plain", raw: "mail/prod", want: "mail/prod"},
		{name: "outer slashes", raw: "/mail/prod/", want: "mail/prod"},
		{name: "slash only", raw: "/", wantErr: true},
		{name: "empty inner segment", raw: "mail//prod", wantErr: true},
		{name: "current segment", raw: "mail/./prod", wantErr: true},
		{name: "parent segment", raw: "mail/../prod", wantErr: true},
		{name: "backslash", raw: `mail\prod`, wantErr: true},
		{name: "query delimiter", raw: "mail?prod", wantErr: true},
		{name: "fragment delimiter", raw: "mail#prod", wantErr: true},
		{name: "percent encoding", raw: "mail/%2e%2e/prod", wantErr: true},
		{name: "outer whitespace", raw: " mail/prod", wantErr: true},
		{name: "control character", raw: "mail/\nprod", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeS3PrefixPath(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("normalizeS3PrefixPath(%q) error = %v, wantErr %v", test.raw, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("normalizeS3PrefixPath(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestS3ObjectKeyPrefix(t *testing.T) {
	ref := Ref(strings.Repeat("a", 64))

	legacy := (&s3Store{}).key(42, ref)
	if want := "42/aa/aa/" + string(ref); legacy != want {
		t.Fatalf("legacy key = %q, want %q", legacy, want)
	}

	prefixed := (&s3Store{prefixPath: "mail/prod"}).key(42, ref)
	if want := "mail/prod/42/aa/aa/" + string(ref); prefixed != want {
		t.Fatalf("prefixed key = %q, want %q", prefixed, want)
	}
}

func TestS3PrefixDoesNotAffectBucketProbe(t *testing.T) {
	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	store, err := NewS3(S3Config{
		Endpoint:   server.URL,
		Region:     "us-east-1",
		Bucket:     "mail-bucket",
		PrefixPath: "/mail/prod/",
		AccessKey:  "access",
		SecretKey:  "secret",
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if gotMethod != http.MethodHead || gotPath != "/mail-bucket" {
		t.Fatalf("bucket probe = %s %s, want HEAD /mail-bucket", gotMethod, gotPath)
	}
	if got := store.(*s3Store).prefixPath; got != "mail/prod" {
		t.Fatalf("normalized store prefix = %q, want mail/prod", got)
	}
}
