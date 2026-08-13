package webapi

import (
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/core/store"
)

func TestCustomerDeliveryAggregation(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		in   []store.OutboundDelivery
		want string
	}{
		{"sending hides queue details", []store.OutboundDelivery{{Status: "queued"}, {Status: "retrying"}}, "sending"},
		{"all delivered", []store.OutboundDelivery{{Status: "delivered"}, {Status: "delivered"}}, "delivered"},
		{"mixed terminal", []store.OutboundDelivery{{Status: "delivered"}, {Status: "failed"}}, "partially_delivered"},
		{"all failed", []store.OutboundDelivery{{Status: "failed", UpdatedAt: now}, {Status: "failed"}}, "not_delivered"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeDelivery(tt.in)
			if got == nil || got.Status != tt.want {
				t.Fatalf("summary = %#v, want %s", got, tt.want)
			}
		})
	}
}
