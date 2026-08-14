package blob

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

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

func TestS3ObjectURLAddressingStyles(t *testing.T) {
	const key = "mail/prod/42/aa/bb/message"
	tests := []struct {
		name               string
		endpoint           string
		bucket             string
		virtualHostedStyle bool
		want               string
	}{
		{
			name:     "path style remains the default",
			endpoint: "http://minio:9000",
			bucket:   "octo-mail",
			want:     "http://minio:9000/octo-mail/" + key,
		},
		{
			name:               "COS virtual-hosted style",
			endpoint:           "https://cos.ap-shanghai.myqcloud.com",
			bucket:             "octo-mail-1250000000",
			virtualHostedStyle: true,
			want:               "https://octo-mail-1250000000.cos.ap-shanghai.myqcloud.com/" + key,
		},
		{
			name:               "virtual-hosted style preserves port and base path",
			endpoint:           "http://s3.internal:9000/base/",
			bucket:             "octo-mail",
			virtualHostedStyle: true,
			want:               "http://octo-mail.s3.internal:9000/base/" + key,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := s3ObjectBaseURL(test.endpoint, test.bucket, test.virtualHostedStyle)
			if err != nil {
				t.Fatalf("object base URL: %v", err)
			}
			got += "/" + key
			if got != test.want {
				t.Fatalf("object URL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestS3VirtualHostedProbe(t *testing.T) {
	objectBaseURL, err := s3ObjectBaseURL(
		"https://cos.ap-shanghai.myqcloud.com",
		"octo-mail-1250000000",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	var request *http.Request
	s := &s3Store{
		client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			request = req.Clone(req.Context())
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Status:     "404 Not Found",
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`,
				)),
				Request: req,
			}, nil
		})},
		objectBaseURL:  objectBaseURL,
		region:         "ap-shanghai",
		bucket:         "octo-mail-1250000000",
		prefixPath:     "mail/prod",
		accessKey:      "access",
		secretKey:      "secret",
		maxAttempts:    1,
		attemptTimeout: time.Second,
		nowFn:          time.Now,
	}

	if err := s.probe(context.Background()); err != nil {
		t.Fatalf("virtual-hosted probe: %v", err)
	}
	if request == nil {
		t.Fatal("probe did not send a request")
	}
	if got, want := request.URL.Host, "octo-mail-1250000000.cos.ap-shanghai.myqcloud.com"; got != want {
		t.Fatalf("probe host = %q, want %q", got, want)
	}
	if request.Host != request.URL.Host {
		t.Fatalf("signed probe host = %q, want request URL host %q", request.Host, request.URL.Host)
	}
	if got, want := request.URL.Path, "/mail/prod/"+s3ProbeObjectName; got != want {
		t.Fatalf("probe path = %q, want %q", got, want)
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

func TestNewS3AllowsAWSMissingObjectMask(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`))
	}))
	t.Cleanup(server.Close)

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	_, err := NewS3(S3Config{
		Endpoint:   server.URL,
		Region:     "us-east-1",
		Bucket:     "mail-bucket",
		PrefixPath: "mail/prod",
		AccessKey:  "access",
		SecretKey:  "secret",
	})
	if err != nil {
		t.Fatalf("NewS3 rejected AWS missing-object mask: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, "AccessDenied") {
		t.Fatalf("startup warning missing AccessDenied context: %s", got)
	}
}
