package submit

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/sasl"
)

// RelayDialer returns a Dialer that ignores the recipient domain and always
// connects to one deployment-configured SMTP relay. The returned hostname is
// the relay's certificate/SNI identity, not the recipient domain.
func RelayDialer(addr string, host dns.Domain) Dialer {
	return func(ctx context.Context, _ string) (net.Conn, dns.Domain, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, dns.Domain{}, fmt.Errorf("dial SMTP relay %s: %w", addr, err)
		}
		return conn, host, nil
	}
}

// RelayAuth selects an authentication mechanism supported by common SMTP
// submission services. Both mechanisms carry reusable credentials and are
// therefore allowed only after a verified TLS connection has been established.
// PLAIN is the standardized mechanism (RFC 4616); LOGIN is a compatibility
// fallback for providers that advertise only LOGIN.
func RelayAuth(username, password string) func([]string, *tls.ConnectionState) (sasl.Client, error) {
	return func(mechanisms []string, state *tls.ConnectionState) (sasl.Client, error) {
		if state == nil || !state.HandshakeComplete {
			return nil, fmt.Errorf("SMTP relay authentication requires TLS")
		}
		supports := func(want string) bool {
			for _, mechanism := range mechanisms {
				if strings.EqualFold(mechanism, want) {
					return true
				}
			}
			return false
		}
		if supports("PLAIN") {
			return sasl.NewClientPlain(username, password), nil
		}
		if supports("LOGIN") {
			return sasl.NewClientLogin(username, password), nil
		}
		return nil, fmt.Errorf("SMTP relay does not advertise a supported authentication mechanism (PLAIN or LOGIN)")
	}
}
