package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestCheckVERPConfig proves the security control that closes the nil-vs-empty
// fail-open seam flagged in review: a bounce domain configured WITHOUT a signing
// key must be refused at startup (not merely warned), because []byte(os.Getenv)
// for an unset/empty env var is non-nil but length 0 — the unsigned, forgeable
// attribution path. The explicit dev escape hatch re-permits it.
func TestCheckVERPConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"disabled: no bounce domain", config{}, false},
		{"signed: key set", config{bounceDomain: "b.example", verpKey: []byte("k")}, false},
		{
			// The exact review scenario: OCTO_MAIL_VERP_KEY unset/empty yields a
			// non-nil, zero-length key. Must be a fatal misconfig, not a warning.
			"unsigned: empty (non-nil) key, no escape hatch → refuse",
			config{bounceDomain: "b.example", verpKey: []byte("")},
			true,
		},
		{
			"unsigned: escape hatch set → allowed",
			config{bounceDomain: "b.example", verpKey: []byte(""), allowUnsignedVERP: true},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVERPConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil (fail-open on forgeable VERP path)")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidateS3CredsFailFast proves #25-5: an S3 endpoint requires BOTH access
// and secret (the hand-rolled SigV4 signer has no ambient-IAM path and the session
// token only augments them), so an endpoint with missing/incomplete static creds
// is a fatal misconfiguration caught at startup rather than at first request.
func TestValidateS3CredsFailFast(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"no s3 at all", config{}, false},
		{"endpoint + static creds", config{s3Endpoint: "http://s3", s3Access: "a", s3Secret: "s"}, false},
		{"endpoint + access+secret+token", config{s3Endpoint: "http://s3", s3Access: "a", s3Secret: "s", s3SessionToken: "t"}, false},
		{"endpoint + session token only → refuse (signer needs secret)", config{s3Endpoint: "http://s3", s3SessionToken: "t"}, true},
		{"endpoint + access but no secret → refuse", config{s3Endpoint: "http://s3", s3Access: "a"}, true},
		{"endpoint + no creds → refuse", config{s3Endpoint: "http://s3"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.cfg, log)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestS3PrefixPathConfig(t *testing.T) {
	t.Setenv("OCTO_MAIL_S3_PREFIX_PATH", "")
	if got := loadConfig().s3PrefixPath; got != "" {
		t.Fatalf("default S3 prefix path = %q, want empty", got)
	}

	t.Setenv("OCTO_MAIL_S3_PREFIX_PATH", "/mail/prod/")
	if got := loadConfig().s3PrefixPath; got != "/mail/prod/" {
		t.Fatalf("configured S3 prefix path = %q, want %q", got, "/mail/prod/")
	}
}

func TestS3ForcePathStyleConfig(t *testing.T) {
	t.Setenv("OCTO_MAIL_S3_FORCE_PATH_STYLE", "")
	if loadConfig().s3VirtualHostedStyle {
		t.Fatal("default S3 addressing mode must remain path style")
	}

	t.Setenv("OCTO_MAIL_S3_FORCE_PATH_STYLE", "1")
	if loadConfig().s3VirtualHostedStyle {
		t.Fatal("OCTO_MAIL_S3_FORCE_PATH_STYLE=1 did not enable path style")
	}

	t.Setenv("OCTO_MAIL_S3_FORCE_PATH_STYLE", "0")
	if !loadConfig().s3VirtualHostedStyle {
		t.Fatal("OCTO_MAIL_S3_FORCE_PATH_STYLE=0 did not enable virtual-hosted style")
	}
}

func TestAutoReplyChainConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	strongKey := []byte(strings.Repeat("k", 32))
	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"disabled without key", config{autoReplyMaxCount: 0}, false},
		{"enabled with strong key", config{autoReplyMaxCount: 4, autoReplyChainKey: strongKey}, false},
		{"enabled without key", config{autoReplyMaxCount: 4}, true},
		{"enabled with weak key", config{autoReplyMaxCount: 4, autoReplyChainKey: []byte("short")}, true},
		{"negative maximum", config{autoReplyMaxCount: -1, autoReplyChainKey: strongKey}, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validate(test.cfg, log)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}

	t.Setenv("OCTO_MAIL_AUTO_REPLY_MAX_COUNT", "")
	t.Setenv("OCTO_MAIL_AUTO_REPLY_CHAIN_KEY", "")
	if got := loadConfig().autoReplyMaxCount; got != 4 {
		t.Fatalf("default auto-reply maximum = %d, want 4", got)
	}
}

func TestAgentMailboxOwnerSpaceLimitConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("OCTO_MAIL_AUTO_REPLY_CHAIN_KEY", strings.Repeat("k", 32))
	t.Setenv("OCTO_MAIL_MAX_AGENT_MAILBOXES_PER_OWNER_SPACE", "")
	if got := loadConfig().maxAgentMailboxesPerOwnerSpace; got != 2 {
		t.Fatalf("default Agent mailbox owner/Space limit = %d, want 2", got)
	}

	t.Setenv("OCTO_MAIL_MAX_AGENT_MAILBOXES_PER_OWNER_SPACE", "7")
	cfg := loadConfig()
	if cfg.maxAgentMailboxesPerOwnerSpace != 7 {
		t.Fatalf("configured Agent mailbox owner/Space limit = %d, want 7", cfg.maxAgentMailboxesPerOwnerSpace)
	}
	if err := validate(cfg, log); err != nil {
		t.Fatalf("valid limit rejected: %v", err)
	}

	for _, invalid := range []string{"0", "-1", "1001", "not-a-number"} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("OCTO_MAIL_MAX_AGENT_MAILBOXES_PER_OWNER_SPACE", invalid)
			if err := validate(loadConfig(), log); err == nil {
				t.Fatalf("invalid limit %q accepted", invalid)
			}
		})
	}
}

func TestAgentMailboxDomainConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("OCTO_MAIL_AUTO_REPLY_CHAIN_KEY", strings.Repeat("k", 32))
	t.Setenv("OCTO_MAIL_AGENT_MAILBOX_DOMAIN", "")
	if got := loadConfig().agentMailboxDomain; got != "" {
		t.Fatalf("default Agent mailbox domain = %q, want empty compatibility mode", got)
	}

	t.Setenv("OCTO_MAIL_AGENT_MAILBOX_DOMAIN", " MAIL.IMOCTO.CN ")
	cfg := loadConfig()
	if cfg.agentMailboxDomain != "mail.imocto.cn" {
		t.Fatalf("configured Agent mailbox domain = %q, want mail.imocto.cn", cfg.agentMailboxDomain)
	}
	if err := validate(cfg, log); err != nil {
		t.Fatalf("valid Agent mailbox domain rejected: %v", err)
	}

	t.Setenv("OCTO_MAIL_AGENT_MAILBOX_DOMAIN", "not a domain")
	if err := validate(loadConfig(), log); err == nil {
		t.Fatal("invalid Agent mailbox domain accepted")
	}
}

func TestMaxMessageSizeConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("OCTO_MAIL_AUTO_REPLY_CHAIN_KEY", strings.Repeat("k", 32))
	t.Setenv("OCTO_MAIL_MAX_SIZE", "52428800")
	if cfg := loadConfig(); cfg.maxSize != 50*1024*1024 {
		t.Fatalf("configured max message size = %d, want %d", cfg.maxSize, int64(50*1024*1024))
	} else if err := validate(cfg, log); err != nil {
		t.Fatalf("valid max message size rejected: %v", err)
	}

	for _, invalid := range []string{"0", "-1", "not-a-number"} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("OCTO_MAIL_MAX_SIZE", invalid)
			if err := validate(loadConfig(), log); err == nil {
				t.Fatalf("invalid max message size %q accepted", invalid)
			}
		})
	}
}

// TestValidateAdminWarnsWhenExposed proves the admin-exposure warning: a
// non-loopback admin listener with no token emits a warning (not a hard error),
// while a loopback bind or a token present is silent.
func TestValidateAdminWarnsWhenExposed(t *testing.T) {
	cases := []struct {
		name     string
		cfg      config
		wantWarn bool
	}{
		{"default :8081 (all ifaces) no token", config{adminAddr: ":8081"}, true},
		{"0.0.0.0 no token", config{adminAddr: "0.0.0.0:8081"}, true},
		{"loopback no token", config{adminAddr: "127.0.0.1:8081"}, false},
		{"ipv6 loopback no token", config{adminAddr: "[::1]:8081"}, false},
		{"localhost no token", config{adminAddr: "localhost:8081"}, false},
		{"all ifaces WITH token", config{adminAddr: ":8081", adminToken: "secret"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			log := slog.New(slog.NewTextHandler(&buf, nil))
			if err := validate(tc.cfg, log); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			warned := strings.Contains(buf.String(), "admin API listens on a non-loopback")
			if warned != tc.wantWarn {
				t.Fatalf("admin warning = %v, want %v (log: %q)", warned, tc.wantWarn, buf.String())
			}
		})
	}
}

// TestIsLoopbackAddr covers the listen-address loopback classifier directly.
func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		":8081":            false, // all interfaces
		"0.0.0.0:8081":     false,
		"[::]:8081":        false,
		"127.0.0.1:8081":   true,
		"[::1]:8081":       true,
		"[::1]":            true,
		"localhost:8081":   true,
		"10.0.0.5:8081":    false,
		"example.com:8081": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

// backend when no S3 endpoint is configured (the shared helper the ops
// subcommands now use, so export/import agree with the serve process instead of
// hardcoding fs). The fs path is exercised directly; the S3 branch is covered by
// storage/blob's own S3 round-trip test.
func TestOpenBlobStoreSelectsBackend(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No S3 endpoint → fs backend rooted at the configured blobDir.
	dir := t.TempDir()
	bs, err := openBlobStore(config{blobDir: dir}, log)
	if err != nil {
		t.Fatalf("fs backend: %v", err)
	}
	if bs == nil {
		t.Fatal("fs backend returned nil store")
	}
	// A round-trip proves it's a working fs store at the right root.
	ref, _, err := bs.Put(context.Background(), 1, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("fs Put: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("blobDir not created: %v", err)
	}
	_ = ref
}

func TestOpenBlobStoreLogsNormalizedS3Prefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>not found</Message></Error>`)
	}))
	t.Cleanup(server.Close)

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	_, err := openBlobStore(config{
		s3Endpoint:   server.URL,
		s3Region:     "us-east-1",
		s3Bucket:     "mail-bucket",
		s3PrefixPath: "/mail/prod/",
		s3Access:     "access",
		s3Secret:     "secret",
	}, log)
	if err != nil {
		t.Fatalf("open S3 backend: %v", err)
	}
	if got := logs.String(); !strings.Contains(got, "prefix_path=mail/prod") {
		t.Fatalf("S3 log does not contain normalized prefix: %s", got)
	}
}
