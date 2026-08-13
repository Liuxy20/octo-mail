package blob

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
		{name: "multiple outer slashes", raw: "///mail/prod///", want: "mail/prod"},
		{name: "allowed segment characters", raw: "Mail_Prod-2.0", want: "Mail_Prod-2.0"},
		{name: "slash only", raw: "/", wantErr: true},
		{name: "empty inner segment", raw: "mail//prod", wantErr: true},
		{name: "current segment", raw: "mail/./prod", wantErr: true},
		{name: "parent segment", raw: "mail/../prod", wantErr: true},
		{name: "backslash", raw: `mail\prod`, wantErr: true},
		{name: "query delimiter", raw: "mail?prod", wantErr: true},
		{name: "fragment delimiter", raw: "mail#prod", wantErr: true},
		{name: "percent encoding", raw: "mail/%2e%2e/prod", wantErr: true},
		{name: "outer whitespace", raw: " mail/prod", wantErr: true},
		{name: "inner whitespace", raw: "mail/pro d", wantErr: true},
		{name: "control character", raw: "mail/\nprod", wantErr: true},
		{name: "tilde", raw: "mail/~prod", wantErr: true},
		{name: "non-ASCII", raw: "mail/生产", wantErr: true},
		{name: "divergent exclamation", raw: "mail/prod!v2", wantErr: true},
		{name: "divergent dollar", raw: "mail/prod$v2", wantErr: true},
		{name: "divergent ampersand", raw: "mail/prod&v2", wantErr: true},
		{name: "divergent apostrophe", raw: "mail/prod'v2", wantErr: true},
		{name: "divergent left parenthesis", raw: "mail/prod(v2", wantErr: true},
		{name: "divergent right parenthesis", raw: "mail/prod)v2", wantErr: true},
		{name: "divergent asterisk", raw: "mail/prod*v2", wantErr: true},
		{name: "divergent plus", raw: "mail/prod+v2", wantErr: true},
		{name: "divergent comma", raw: "mail/prod,v2", wantErr: true},
		{name: "divergent semicolon", raw: "mail/prod;v2", wantErr: true},
		{name: "divergent equals", raw: "mail/prod=v2", wantErr: true},
		{name: "divergent colon", raw: "mail/prod:v2", wantErr: true},
		{name: "divergent at sign", raw: "mail/prod@v2", wantErr: true},
		{name: "divergent left bracket", raw: "mail/prod[v2", wantErr: true},
		{name: "divergent right bracket", raw: "mail/prod]v2", wantErr: true},
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

func TestNewS3DoesNotSendBucketRequests(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
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
	if got := requests.Load(); got != 0 {
		t.Fatalf("NewS3 sent %d request(s), want none; bucket provisioning belongs to deployment infrastructure", got)
	}
	if got := store.(*s3Store).prefixPath; got != "mail/prod" {
		t.Fatalf("normalized store prefix = %q, want mail/prod", got)
	}
}
