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

func TestNewS3UsesReadOnlyObjectProbe(t *testing.T) {
	var requests []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`))
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
	if len(requests) != 1 {
		t.Fatalf("NewS3 sent %d request(s), want one object-level probe", len(requests))
	}
	req := requests[0]
	if req.Method != http.MethodGet {
		t.Fatalf("probe method = %s, want GET", req.Method)
	}
	if got, want := req.URL.Path, "/mail-bucket/mail/prod/"+s3ProbeObjectName; got != want {
		t.Fatalf("probe path = %q, want %q", got, want)
	}
	if req.URL.Path == "/mail-bucket" || req.URL.Path == "/mail-bucket/" {
		t.Fatalf("probe unexpectedly targeted bucket root: %q", req.URL.Path)
	}
	if got := store.(*s3Store).prefixPath; got != "mail/prod" {
		t.Fatalf("normalized store prefix = %q, want mail/prod", got)
	}
}

func TestNewS3FailsClosedOnObjectProbeErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		code   string
	}{
		{name: "missing bucket", status: http.StatusNotFound, code: "NoSuchBucket"},
		{name: "access denied", status: http.StatusForbidden, code: "AccessDenied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("probe method = %s, want GET", r.Method)
				}
				if r.URL.Path != "/mail-bucket/"+s3ProbeObjectName {
					t.Errorf("probe path = %q, want object path", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(`<Error><Code>` + test.code + `</Code><Message>probe failed</Message></Error>`))
			}))
			t.Cleanup(server.Close)

			_, err := NewS3(S3Config{
				Endpoint:  server.URL,
				Region:    "us-east-1",
				Bucket:    "mail-bucket",
				AccessKey: "access",
				SecretKey: "secret",
			})
			if err == nil {
				t.Fatalf("NewS3 succeeded for %s; want fail-closed startup error", test.code)
			}
			if !strings.Contains(err.Error(), test.code) {
				t.Fatalf("NewS3 error = %q, want S3 code %q", err, test.code)
			}
		})
	}
}
