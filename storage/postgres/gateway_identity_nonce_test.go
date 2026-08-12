package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestGatewayAssertionNonceReplayUsesApplicationClock(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.Pool.Exec(ctx, `TRUNCATE gateway_assertion_nonces`); err != nil {
		t.Fatal(err)
	}

	var databaseNow time.Time
	if err := store.Pool.QueryRow(ctx, `SELECT now()`).Scan(&databaseNow); err != nil {
		t.Fatal(err)
	}
	// Simulate an application process whose clock is five minutes behind
	// PostgreSQL. The assertion is valid for the application for one more minute,
	// even though its expires_at is already in PostgreSQL's past.
	applicationNow := databaseNow.Add(-5 * time.Minute)
	expiresAt := applicationNow.Add(time.Minute)
	directory := store.NewDirectory()
	if err := directory.ConsumeGatewayAssertionNonce(ctx, "octo-server", "nonce-a", expiresAt, applicationNow); err != nil {
		t.Fatalf("first nonce consumption: %v", err)
	}
	if err := directory.ConsumeGatewayAssertionNonce(ctx, "octo-server", "nonce-a", expiresAt, applicationNow); err == nil {
		t.Fatal("replay accepted when PostgreSQL clock leads application clock")
	}
}

func TestGatewayAssertionNonceReplaySurvivesCrossNodeClockSkew(t *testing.T) {
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.Pool.Exec(ctx, `TRUNCATE gateway_assertion_nonces`); err != nil {
		t.Fatal(err)
	}

	directory := store.NewDirectory()
	slowNow := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	expiresAt := slowNow.Add(time.Minute)
	if err := directory.ConsumeGatewayAssertionNonce(ctx, "octo-server", "nonce-a", expiresAt, slowNow); err != nil {
		t.Fatalf("first nonce consumption: %v", err)
	}

	// A faster node processes unrelated traffic after nonce-a's signed expiry.
	// Cleanup must retain nonce-a because a slower node can still consider the
	// original assertion valid according to its own verification clock.
	fastNow := expiresAt.Add(90 * time.Second)
	if err := directory.ConsumeGatewayAssertionNonce(ctx, "octo-server", "nonce-b", fastNow.Add(time.Minute), fastNow); err != nil {
		t.Fatalf("fast-node nonce consumption: %v", err)
	}
	if err := directory.ConsumeGatewayAssertionNonce(ctx, "octo-server", "nonce-a", expiresAt, slowNow.Add(30*time.Second)); err == nil {
		t.Fatal("replay accepted after a faster node ran nonce cleanup")
	}
}
