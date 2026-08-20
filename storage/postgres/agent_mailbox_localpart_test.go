package postgres

import (
	"strings"
	"testing"
)

func TestValidAgentMailboxLocalpart(t *testing.T) {
	tests := []struct {
		name      string
		localpart string
		want      bool
	}{
		{name: "minimum length", localpart: "agent", want: true},
		{name: "common business role", localpart: "support", want: true},
		{name: "allowed separators", localpart: "agent.alerts_1", want: true},
		{name: "too short", localpart: "bot1", want: false},
		{name: "reserved admin", localpart: "admin", want: false},
		{name: "reserved postmaster", localpart: "postmaster", want: false},
		{name: "consecutive dots", localpart: "agent..alerts", want: false},
		{name: "too long", localpart: strings.Repeat("a", 65), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validAgentMailboxLocalpart(test.localpart); got != test.want {
				t.Fatalf("validAgentMailboxLocalpart(%q) = %v, want %v", test.localpart, got, test.want)
			}
		})
	}
}
