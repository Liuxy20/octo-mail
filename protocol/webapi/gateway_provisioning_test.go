package webapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/directory"
	"github.com/Mininglamp-OSS/octo-mail/security/gatewayassert"
	"github.com/mjl-/mox/smtp"
)

func TestGatewayProvisioningRequiresSignedRequestAndUsesClaims(t *testing.T) {
	secret := []byte(strings.Repeat("g", 32))
	dir := &gatewayProvisioningStub{
		result: directory.GatewayProvisioningResult{
			TenantID: 1, PrincipalID: 2, DefaultAccountID: 3,
			Address: "alice@owners.example", Created: true,
		},
	}
	srv := &Server{Dir: dir, GatewaySecret: secret, AgentMailboxDomain: "owners.example"}
	body := []byte(`{"localpart":"alice"}`)
	token, err := gatewayassert.Sign(secret, "octo-server", "user-a", "space-a", http.MethodPost,
		"/internal/v0/gateway-identities/ensure", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/v0/gateway-identities/ensure", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if dir.calls != 1 {
		t.Fatalf("provision calls = %d, want 1", dir.calls)
	}
	if dir.input.Issuer != "octo-server" || dir.input.Subject != "user-a" || dir.input.SpaceID != "space-a" ||
		dir.input.Localpart != "alice" || dir.input.Domain != "owners.example" {
		t.Fatalf("provision input = %#v", dir.input)
	}

	// A consumed assertion cannot be replayed, even with the same exact body.
	replay := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, "/internal/v0/gateway-identities/ensure", bytes.NewReader(body))
	replayRequest.Header.Set("Authorization", "Bearer "+token)
	srv.Handler().ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusUnauthorized || dir.calls != 1 {
		t.Fatalf("replay = status %d calls %d body %s", replay.Code, dir.calls, replay.Body.String())
	}
}

func TestGatewayProvisioningRejectsTamperingAndUnknownInput(t *testing.T) {
	secret := []byte(strings.Repeat("g", 32))
	for name, test := range map[string]struct {
		signedBody  []byte
		requestBody []byte
		authorize   bool
		wantStatus  int
	}{
		"missing assertion": {requestBody: []byte(`{"localpart":"alice"}`), wantStatus: http.StatusUnauthorized},
		"tampered body": {
			signedBody: []byte(`{"localpart":"alice"}`), requestBody: []byte(`{"localpart":"mallory"}`),
			authorize: true, wantStatus: http.StatusUnauthorized,
		},
		"unknown field": {
			signedBody:  []byte(`{"localpart":"alice","tenantId":99}`),
			requestBody: []byte(`{"localpart":"alice","tenantId":99}`),
			authorize:   true, wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := &gatewayProvisioningStub{}
			srv := &Server{Dir: dir, GatewaySecret: secret, AgentMailboxDomain: "owners.example"}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/internal/v0/gateway-identities/ensure", bytes.NewReader(test.requestBody))
			if test.authorize {
				token, err := gatewayassert.Sign(secret, "octo-server", "user-a", "space-a", http.MethodPost,
					"/internal/v0/gateway-identities/ensure", test.signedBody, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer "+token)
			}
			srv.Handler().ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
			if dir.calls != 0 {
				t.Fatalf("invalid request reached provisioner %d times", dir.calls)
			}
		})
	}
}

type gatewayProvisioningStub struct {
	mu        sync.Mutex
	nonces    map[string]struct{}
	input     directory.GatewayProvisioningInput
	result    directory.GatewayProvisioningResult
	resultErr error
	calls     int
}

func (d *gatewayProvisioningStub) AuthenticatePrincipal(context.Context, string, directory.Credential) (directory.TenantScope, directory.Principal, error) {
	return nil, directory.Principal{}, errors.New("not implemented")
}

func (d *gatewayProvisioningStub) AuthenticateAPIKey(context.Context, string) (directory.TenantScope, directory.Principal, int64, error) {
	return nil, directory.Principal{}, 0, errors.New("not implemented")
}

func (d *gatewayProvisioningStub) ResolveInbound(context.Context, smtp.Path) (directory.InboundTarget, error) {
	return nil, errors.New("not implemented")
}

func (d *gatewayProvisioningStub) ConsumeGatewayAssertionNonce(_ context.Context, issuer, nonce string, _ time.Time, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nonces == nil {
		d.nonces = make(map[string]struct{})
	}
	key := issuer + "\x00" + nonce
	if _, exists := d.nonces[key]; exists {
		return errors.New("replayed")
	}
	d.nonces[key] = struct{}{}
	return nil
}

func (d *gatewayProvisioningStub) EnsureGatewayIdentity(_ context.Context, input directory.GatewayProvisioningInput) (directory.GatewayProvisioningResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	d.input = input
	return d.result, d.resultErr
}
