package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestCreateAgentAuthorizationCleansExpiredRequests(t *testing.T) {
	ctx := context.Background()
	bs, _ := blob.NewFS(t.TempDir())
	s, err := Open(ctx, testDSN, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	defer s.Close()
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO agent_auth_requests
		 (device_hash,user_code,bot_id,space_id,code_challenge,expires_at)
		 VALUES (decode('01','hex'),'OLD001','old-bot','space-a','challenge',now()-interval '2 days'),
		        (decode('02','hex'),'RECENT','recent-bot','space-a','challenge',now()-interval '1 hour')`); err != nil {
		t.Fatal(err)
	}

	challenge := sha256.Sum256([]byte("cleanup-verifier"))
	if _, err := s.NewDirectory().CreateAgentAuthorization(ctx, directory.AgentAuthorizationInput{
		BotID: "new-bot", SpaceID: "space-a",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]),
	}); err != nil {
		t.Fatal(err)
	}

	var oldRows, recentRows int
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FILTER (WHERE user_code='OLD001'),
		        count(*) FILTER (WHERE user_code='RECENT')
		 FROM agent_auth_requests`).Scan(&oldRows, &recentRows); err != nil {
		t.Fatal(err)
	}
	if oldRows != 0 || recentRows != 1 {
		t.Fatalf("expired/recent authorization rows = %d/%d, want 0/1", oldRows, recentRows)
	}
}
