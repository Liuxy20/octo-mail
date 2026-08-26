package webapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJunkAllowlistOperationsRequireHumanOwner(t *testing.T) {
	s := &Server{}
	agent := authCtx{agentCredentialID: 7}
	tests := []struct {
		name string
		call func() error
	}{
		{"restore", func() error {
			req := httptest.NewRequest(http.MethodPost, "/webapi/v0/messages/E1/not-junk", nil)
			req.SetPathValue("id", "E1")
			_, _, err := s.restoreNotJunk(context.Background(), agent, req)
			return err
		}},
		{"list", func() error {
			_, _, err := s.listJunkAllowedSenders(context.Background(), agent, httptest.NewRequest(http.MethodGet, "/webapi/v0/junk-allowlist", nil))
			return err
		}},
		{"remove", func() error {
			req := httptest.NewRequest(http.MethodDelete, "/webapi/v0/junk-allowlist/sender@example.com", nil)
			req.SetPathValue("address", "sender@example.com")
			_, _, err := s.removeJunkAllowedSender(context.Background(), agent, req)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			statusErr, ok := err.(*statusError)
			if !ok {
				t.Fatalf("agent authorization error = %T, want *statusError", err)
			}
			if statusErr.status != http.StatusForbidden || statusErr.code != "human_owner_required" {
				t.Fatalf("agent authorization error = %#v, want 403 human_owner_required", statusErr)
			}
		})
	}
}
