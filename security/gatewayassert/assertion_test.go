package gatewayassert

import (
	"strings"
	"testing"
	"time"
)

const octoServerFixedVector = "omg_eyJ2IjoxLCJpc3MiOiJvY3RvLXNlcnZlciIsInN1YiI6InVzZXItYSIsInNwYWNlIjoic3BhY2UtYSIsIm1ldGhvZCI6IlBPU1QiLCJ1cmkiOiIvd2ViYXBpL3YwL21lc3NhZ2VzP3g9MSIsImJvZHlfc2hhMjU2IjoiMjMwZDgzNThkYzhlODg5MGI0YzU4ZGVlYjYyOTEyZWUyZjIwMzU3YWU5MmE1Y2M4NjFiOThlNjhmZTMxYWNiNSIsImlhdCI6MTc4NTMxOTIwMCwiZXhwIjoxNzg1MzE5MjYwLCJub25jZSI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHcifQ.djWC9k17lq-g2zuKORkSnQUuEKZK9dIYl8ktFBHSqIc"

func TestVerifyAcceptsOctoServerFixedWireVector(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Date(2026, 7, 29, 10, 0, 30, 0, time.UTC)
	claims, err := Verify(secret, octoServerFixedVector, "POST", "/webapi/v0/messages?x=1", []byte("body"), now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "octo-server" || claims.Subject != "user-a" || claims.SpaceID != "space-a" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestSignVerifyBindsIdentityAndRequest(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	now := time.Date(2026, 7, 29, 10, 0, 0, 0, time.UTC)
	token, err := Sign(secret, "octo-server", "user-a", "space-a", "post", "/webapi/v0/messages?x=1", []byte("body"), now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(secret, token, "POST", "/webapi/v0/messages?x=1", []byte("body"), now.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-a" || claims.SpaceID != "space-a" || claims.Issuer != "octo-server" {
		t.Fatalf("claims = %#v", claims)
	}
	for name, verify := range map[string]func() error{
		"method": func() error {
			_, err := Verify(secret, token, "GET", "/webapi/v0/messages?x=1", []byte("body"), now)
			return err
		},
		"uri": func() error {
			_, err := Verify(secret, token, "POST", "/webapi/v0/messages?x=2", []byte("body"), now)
			return err
		},
		"body": func() error {
			_, err := Verify(secret, token, "POST", "/webapi/v0/messages?x=1", []byte("changed"), now)
			return err
		},
		"secret": func() error {
			_, err := Verify([]byte(strings.Repeat("x", 32)), token, "POST", "/webapi/v0/messages?x=1", []byte("body"), now)
			return err
		},
		"expiry": func() error {
			_, err := Verify(secret, token, "POST", "/webapi/v0/messages?x=1", []byte("body"), now.Add(2*time.Minute))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := verify(); err == nil {
				t.Fatal("tampered assertion accepted")
			}
		})
	}
}

func TestSignRejectsWeakOrIncompleteInput(t *testing.T) {
	valid := []byte(strings.Repeat("s", 32))
	for name, test := range map[string]struct {
		secret                 []byte
		issuer, subject, space string
	}{
		"weak secret": {[]byte("short"), "octo", "u", "s"},
		"issuer":      {valid, "", "u", "s"},
		"subject":     {valid, "octo", "", "s"},
		"space":       {valid, "octo", "u", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(test.secret, test.issuer, test.subject, test.space, "GET", "/x", nil, time.Now()); err == nil {
				t.Fatal("invalid assertion input accepted")
			}
		})
	}
}
