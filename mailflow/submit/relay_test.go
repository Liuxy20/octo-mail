package submit_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-mail/mailflow/queue"
	"github.com/Mininglamp-OSS/octo-mail/mailflow/submit"
	"github.com/Mininglamp-OSS/octo-mail/storage/blob"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtpclient"
)

type relayObservation struct {
	firstByte byte
	username  string
	password  string
	mailFrom  string
	rcptTo    string
	body      string
}

type prefixedConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type relayHarness struct {
	addr  string
	roots *x509.CertPool
	obs   chan relayObservation
	done  chan error
}

func newRelayHarness(t *testing.T, mechanisms string) relayHarness {
	t.Helper()
	cert, roots := relayCertificate(t, "relay.test")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	h := relayHarness{
		addr:  listener.Addr().String(),
		roots: roots,
		obs:   make(chan relayObservation, 1),
		done:  make(chan error, 1),
	}
	go func() {
		h.done <- serveRelayOnce(listener, cert, mechanisms, h.obs)
	}()
	return h
}

func serveRelayOnce(listener net.Listener, cert tls.Certificate, mechanisms string, observations chan<- relayObservation) error {
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	first := []byte{0}
	if _, err := io.ReadFull(raw, first); err != nil {
		return fmt.Errorf("read first client byte: %w", err)
	}
	obs := relayObservation{firstByte: first[0]}
	conn := tls.Server(&prefixedConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(first), raw)}, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("relay TLS handshake: %w", err)
	}
	reader := bufio.NewReader(conn)
	write := func(line string) error {
		_, err := io.WriteString(conn, line+"\r\n")
		return err
	}
	read := func() (string, error) {
		line, err := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	if err := write("220 relay.test ESMTP"); err != nil {
		return err
	}
	line, err := read()
	if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
		return fmt.Errorf("expected EHLO, got %q: %w", line, err)
	}
	if err := write("250-relay.test"); err != nil {
		return err
	}
	if mechanisms != "" {
		if err := write("250-AUTH " + mechanisms); err != nil {
			return err
		}
	}
	if err := write("250 SIZE 1048576"); err != nil {
		return err
	}

	line, err = read()
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(strings.ToUpper(line), "AUTH PLAIN "):
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN "):]))
		if err != nil {
			return err
		}
		parts := bytes.Split(decoded, []byte{0})
		if len(parts) != 3 {
			return fmt.Errorf("invalid AUTH PLAIN payload")
		}
		obs.username, obs.password = string(parts[1]), string(parts[2])
		if err := write("235 2.7.0 authenticated"); err != nil {
			return err
		}
	case strings.HasPrefix(strings.ToUpper(line), "AUTH LOGIN "):
		username, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH LOGIN "):]))
		if err != nil {
			return err
		}
		obs.username = string(username)
		if err := write("334 " + base64.StdEncoding.EncodeToString([]byte("Password:"))); err != nil {
			return err
		}
		line, err = read()
		if err != nil {
			return err
		}
		password, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			return err
		}
		obs.password = string(password)
		if err := write("235 2.7.0 authenticated"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("expected supported AUTH, got %q", line)
	}

	line, err = read()
	if err != nil || !strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:") {
		return fmt.Errorf("expected MAIL FROM, got %q: %w", line, err)
	}
	obs.mailFrom = line
	if err := write("250 2.1.0 sender ok"); err != nil {
		return err
	}
	line, err = read()
	if err != nil || !strings.HasPrefix(strings.ToUpper(line), "RCPT TO:") {
		return fmt.Errorf("expected RCPT TO, got %q: %w", line, err)
	}
	obs.rcptTo = line
	if err := write("250 2.1.5 recipient ok"); err != nil {
		return err
	}
	line, err = read()
	if err != nil || strings.ToUpper(line) != "DATA" {
		return fmt.Errorf("expected DATA, got %q: %w", line, err)
	}
	if err := write("354 end with dot"); err != nil {
		return err
	}
	var body strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == ".\r\n" {
			break
		}
		body.WriteString(line)
	}
	obs.body = body.String()
	if err := write("250 2.0.0 queued"); err != nil {
		return err
	}
	observations <- obs
	return nil
}

func relayCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append relay test certificate")
	}
	return cert, roots
}

func TestRelayDialerUsesFixedEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			close(accepted)
			_ = conn.Close()
		}
	}()
	dial := submit.RelayDialer(listener.Addr().String(), dns.Domain{ASCII: "relay.test"})
	conn, host, err := dial(context.Background(), "recipient.example")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if host.ASCII != "relay.test" {
		t.Fatalf("remote host = %q", host.ASCII)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("fixed relay endpoint was not dialed")
	}
}

func TestRelayAuthRequiresTLSAndSelectsMechanism(t *testing.T) {
	auth := submit.RelayAuth("mailer", "secret")
	if _, err := auth([]string{"PLAIN"}, nil); err == nil {
		t.Fatal("AUTH PLAIN accepted without TLS")
	}
	tlsState := &tls.ConnectionState{HandshakeComplete: true}
	client, err := auth([]string{"LOGIN", "PLAIN"}, tlsState)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := client.Info(); name != "PLAIN" {
		t.Fatalf("selected %q, want PLAIN", name)
	}
	client, err = auth([]string{"LOGIN"}, tlsState)
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := client.Info(); name != "LOGIN" {
		t.Fatalf("selected %q, want LOGIN", name)
	}
	if _, err := auth([]string{"CRAM-MD5"}, tlsState); err == nil {
		t.Fatal("unsupported relay mechanism accepted")
	}
}

func TestSMTPRelayImplicitTLSAuthAndDelivery(t *testing.T) {
	for _, mechanisms := range []string{"PLAIN LOGIN", "LOGIN"} {
		t.Run(mechanisms, func(t *testing.T) {
			testSMTPRelayDelivery(t, mechanisms)
		})
	}
}

func testSMTPRelayDelivery(t *testing.T, mechanisms string) {
	t.Helper()
	h := newRelayHarness(t, mechanisms)
	ctx := context.Background()
	bs, err := blob.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw := "From: sender@sender.example\r\nTo: recipient@recipient.example\r\nSubject: relay\r\n\r\nhello over implicit TLS\r\n"
	ref, size, err := bs.Put(ctx, 1, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	deliverer := &submit.SMTPDeliverer{
		Blob:          bs,
		Dial:          submit.RelayDialer(h.addr, dns.Domain{ASCII: "relay.test"}),
		EHLOHostname:  dns.Domain{ASCII: "sender.example"},
		TLSMode:       smtpclient.TLSImmediate,
		TLSVerifyPKIX: true,
		TLSConfig: &tls.Config{
			ServerName: "relay.test",
			RootCAs:    h.roots,
			MinVersion: tls.VersionTLS12,
		},
		Auth: submit.RelayAuth("mailer", "relay-secret"),
	}
	allowPlaintext := false
	err = deliverer.Deliver(ctx, queue.Msg{
		TenantID: 1, AccountID: 1,
		MailFrom: "sender@sender.example", RcptTo: "recipient@recipient.example",
		BlobRef: string(ref), Size: size, RequireTLS: &allowPlaintext,
	})
	if err != nil {
		t.Fatalf("relay delivery: %v", err)
	}
	select {
	case obs := <-h.obs:
		if obs.firstByte != 0x16 {
			t.Fatalf("first client byte = 0x%x, want TLS handshake record 0x16", obs.firstByte)
		}
		if obs.username != "mailer" || obs.password != "relay-secret" {
			t.Fatalf("relay credentials = %q/%q", obs.username, obs.password)
		}
		if !strings.Contains(obs.mailFrom, "sender@sender.example") || !strings.Contains(obs.rcptTo, "recipient@recipient.example") {
			t.Fatalf("SMTP envelope = %q / %q", obs.mailFrom, obs.rcptTo)
		}
		if !strings.Contains(obs.body, "hello over implicit TLS") {
			t.Fatalf("relay body = %q", obs.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not receive message")
	}
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay server did not finish")
	}
}

func TestSMTPRelayRejectsUntrustedOrWrongHostCertificate(t *testing.T) {
	tests := []struct {
		name string
		tls  func(*x509.CertPool) *tls.Config
	}{
		{name: "unknown CA", tls: func(_ *x509.CertPool) *tls.Config {
			return &tls.Config{ServerName: "relay.test", RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
		}},
		{name: "wrong hostname", tls: func(roots *x509.CertPool) *tls.Config {
			return &tls.Config{ServerName: "other.test", RootCAs: roots, MinVersion: tls.VersionTLS12}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newRelayHarness(t, "PLAIN")
			ctx := context.Background()
			bs, err := blob.NewFS(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			ref, size, err := bs.Put(ctx, 1, strings.NewReader("From: a@sender.example\r\nTo: b@recipient.example\r\n\r\nx\r\n"))
			if err != nil {
				t.Fatal(err)
			}
			d := &submit.SMTPDeliverer{
				Blob: bs, Dial: submit.RelayDialer(h.addr, dns.Domain{ASCII: "relay.test"}),
				EHLOHostname: dns.Domain{ASCII: "sender.example"}, TLSMode: smtpclient.TLSImmediate,
				TLSVerifyPKIX: true, TLSConfig: test.tls(h.roots), Auth: submit.RelayAuth("mailer", "secret"),
			}
			if err := d.Deliver(ctx, queue.Msg{TenantID: 1, AccountID: 1, MailFrom: "a@sender.example", RcptTo: "b@recipient.example", BlobRef: string(ref), Size: size}); err == nil {
				t.Fatal("relay accepted invalid certificate")
			}
		})
	}
}
