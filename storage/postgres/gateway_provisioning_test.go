package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/core/store"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
)

func TestEnsureGatewayIdentityCreatesAndReusesOwner(t *testing.T) {
	ctx := context.Background()
	s := openGatewayProvisioningStore(t, ctx)
	tenantID, _ := seedGatewayProvisioningDomain(t, ctx, s, "owners.example")
	dir := s.NewDirectory()
	input := directory.GatewayProvisioningInput{
		Issuer: "octo-server", Subject: "user-a", SpaceID: "space-a",
		Localpart: "alice", Domain: "owners.example",
	}

	created, err := dir.EnsureGatewayIdentity(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Created || created.TenantID != tenantID || created.Address != "alice@owners.example" ||
		created.PrincipalID == 0 || created.DefaultAccountID == 0 {
		t.Fatalf("created result = %#v", created)
	}
	assertGatewayOwnerInbox(t, ctx, s, created.DefaultAccountID)

	again, err := dir.EnsureGatewayIdentity(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.PrincipalID != created.PrincipalID || again.DefaultAccountID != created.DefaultAccountID || again.Address != created.Address {
		t.Fatalf("idempotent result = %#v, want owner %#v", again, created)
	}

	input.SpaceID = "space-b"
	secondSpace, err := dir.EnsureGatewayIdentity(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !secondSpace.Created || secondSpace.PrincipalID == created.PrincipalID || secondSpace.DefaultAccountID == created.DefaultAccountID || secondSpace.Address == created.Address {
		t.Fatalf("second Space result = %#v, want an isolated owner account from %#v", secondSpace, created)
	}
	if _, _, accountID, err := dir.AuthenticateGatewayIdentity(ctx, input.Issuer, input.Subject, "space-a", 0); err != nil || accountID != created.DefaultAccountID {
		t.Fatalf("Space A authentication = account %d err %v, want %d", accountID, err, created.DefaultAccountID)
	}
	if _, _, _, err := dir.AuthenticateGatewayIdentity(ctx, input.Issuer, input.Subject, "space-a", secondSpace.DefaultAccountID); err == nil {
		t.Fatal("Space A selected Space B's provisioned account")
	}
	assertGatewayProvisioningCounts(t, ctx, s, 2, 2, 2, 2)
}

func TestEnsureGatewayIdentityConcurrentFirstUse(t *testing.T) {
	ctx := context.Background()
	s := openGatewayProvisioningStore(t, ctx)
	seedGatewayProvisioningDomain(t, ctx, s, "owners.example")
	dir := s.NewDirectory()
	input := directory.GatewayProvisioningInput{
		Issuer: "octo-server", Subject: "user-concurrent", SpaceID: "space-a",
		Localpart: "concurrent", Domain: "owners.example",
	}

	const workers = 8
	results := make(chan directory.GatewayProvisioningResult, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := dir.EnsureGatewayIdentity(ctx, input)
			if err != nil {
				errs <- err
				return
			}
			results <- result
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent ensure: %v", err)
	}
	var accountID int64
	for result := range results {
		if accountID == 0 {
			accountID = result.DefaultAccountID
		}
		if result.DefaultAccountID != accountID {
			t.Errorf("account id = %d, want %d", result.DefaultAccountID, accountID)
		}
	}
	if t.Failed() {
		return
	}
	assertGatewayProvisioningCounts(t, ctx, s, 1, 1, 1, 1)
}

func TestEnsureGatewayIdentityKeepsExistingManualBinding(t *testing.T) {
	ctx := context.Background()
	s := openGatewayProvisioningStore(t, ctx)
	tenantID, domainID := seedGatewayProvisioningDomain(t, ctx, s, "owners.example")
	var principalID, accountID int64
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,'manual@owners.example') RETURNING id`,
		tenantID).Scan(&principalID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$2,'manual') RETURNING id`, tenantID, principalID).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'manual')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','user-manual','space-a',$1,$2,$3)`,
		tenantID, principalID, accountID); err != nil {
		t.Fatal(err)
	}

	result, err := s.NewDirectory().EnsureGatewayIdentity(ctx, directory.GatewayProvisioningInput{
		Issuer: "octo-server", Subject: "user-manual", SpaceID: "space-a",
		Localpart: "different", Domain: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Created || result.PrincipalID != principalID || result.DefaultAccountID != accountID || result.Address != "manual@owners.example" {
		t.Fatalf("manual binding result = %#v", result)
	}
	assertGatewayProvisioningCounts(t, ctx, s, 1, 1, 1, 1)
}

func TestEnsureGatewayIdentityCollisionAndFailures(t *testing.T) {
	ctx := context.Background()
	s := openGatewayProvisioningStore(t, ctx)
	tenantID, domainID := seedGatewayProvisioningDomain(t, ctx, s, "owners.example")
	var occupiedAccount int64
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,name) VALUES ($1,'occupied') RETURNING id`, tenantID).Scan(&occupiedAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'alice')`,
		tenantID, domainID, occupiedAccount); err != nil {
		t.Fatal(err)
	}
	dir := s.NewDirectory()
	input := directory.GatewayProvisioningInput{
		Issuer: "octo-server", Subject: "user-a", SpaceID: "space-a",
		Localpart: "alice", Domain: "owners.example",
	}
	result, err := dir.EnsureGatewayIdentity(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Address == "alice@owners.example" || result.Address == "" {
		t.Fatalf("collision address = %q, want deterministic suffixed address", result.Address)
	}
	if _, err := s.Pool.Exec(ctx,
		`UPDATE gateway_identities SET disabled=true WHERE issuer=$1 AND subject=$2 AND space_id=$3`,
		input.Issuer, input.Subject, input.SpaceID); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.EnsureGatewayIdentity(ctx, input); !errors.Is(err, directory.ErrGatewayIdentityDisabled) {
		t.Fatalf("disabled ensure error = %v, want ErrGatewayIdentityDisabled", err)
	}

	missing := input
	missing.Subject = "user-missing-domain"
	missing.SpaceID = "space-b"
	missing.Domain = "missing.example"
	if _, err := dir.EnsureGatewayIdentity(ctx, missing); !errors.Is(err, directory.ErrAgentMailboxDomainNotFound) {
		t.Fatalf("missing domain error = %v, want ErrAgentMailboxDomainNotFound", err)
	}
	invalid := input
	invalid.Subject = "user-invalid"
	invalid.SpaceID = "space-c"
	invalid.Localpart = "Bad Localpart"
	if _, err := dir.EnsureGatewayIdentity(ctx, invalid); !errors.Is(err, directory.ErrInvalidLocalpart) {
		t.Fatalf("invalid localpart error = %v, want ErrInvalidLocalpart", err)
	}
	assertGatewayProvisioningCounts(t, ctx, s, 1, 2, 2, 1)
}

func TestEnsureGatewayIdentityRejectsInconsistentManualBinding(t *testing.T) {
	ctx := context.Background()
	s := openGatewayProvisioningStore(t, ctx)
	tenantID, domainID := seedGatewayProvisioningDomain(t, ctx, s, "owners.example")

	var ownerPrincipalID, otherPrincipalID, accountID int64
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,'owner@owners.example') RETURNING id`,
		tenantID).Scan(&ownerPrincipalID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO principals (tenant_id,login) VALUES ($1,'other@owners.example') RETURNING id`,
		tenantID).Scan(&otherPrincipalID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO accounts (tenant_id,principal_id,owner_principal_id,name)
		 VALUES ($1,$2,$2,'other') RETURNING id`, tenantID, otherPrincipalID).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO addresses (tenant_id,domain_id,account_id,localpart) VALUES ($1,$2,$3,'other')`,
		tenantID, domainID, accountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO gateway_identities
		 (issuer,subject,space_id,tenant_id,owner_principal_id,default_account_id)
		 VALUES ('octo-server','user-inconsistent','space-a',$1,$2,$3)`,
		tenantID, ownerPrincipalID, accountID); err != nil {
		t.Fatal(err)
	}

	_, err := s.NewDirectory().EnsureGatewayIdentity(ctx, directory.GatewayProvisioningInput{
		Issuer: "octo-server", Subject: "user-inconsistent", SpaceID: "space-a",
		Localpart: "owner", Domain: "owners.example",
	})
	if !errors.Is(err, directory.ErrGatewayProvisioningConflict) {
		t.Fatalf("inconsistent binding error = %v, want ErrGatewayProvisioningConflict", err)
	}
}

func openGatewayProvisioningStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	dsn := os.Getenv("OCTO_MAIL_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://octo_mail:octo_mail@localhost:55432/octo_mail"
	}
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dsn, bs)
	if err != nil {
		t.Skipf("postgres not available (%v)", err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Pool.Exec(ctx, `TRUNCATE tenants RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	return s
}

func seedGatewayProvisioningDomain(t *testing.T, ctx context.Context, s *Store, domainName string) (int64, int64) {
	t.Helper()
	var tenantID, domainID int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id`, "tenant-"+domainName).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if err := s.Pool.QueryRow(ctx,
		`INSERT INTO domains (tenant_id,domain) VALUES ($1,$2) RETURNING id`,
		tenantID, domainName).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	return tenantID, domainID
}

func assertGatewayOwnerInbox(t *testing.T, ctx context.Context, s *Store, accountID int64) {
	t.Helper()
	acc, _, _, err := s.LookupAccountByID(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.ReadTx(ctx, func(tx store.Tx) error {
		mailbox, err := acc.MailboxFind(tx, "Inbox")
		if err != nil {
			return err
		}
		if mailbox == nil {
			return fmt.Errorf("Inbox was not provisioned")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertGatewayProvisioningCounts(t *testing.T, ctx context.Context, s *Store, principals, accounts, addresses, identities int) {
	t.Helper()
	for table, want := range map[string]int{
		"principals": principals, "accounts": accounts, "addresses": addresses, "gateway_identities": identities,
	} {
		var got int
		if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s count = %d, want %d", table, got, want)
		}
	}
}
