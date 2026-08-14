# Design

## Configuration boundary

The composition root owns three deployment secrets/settings:

```text
OCTO_MAIL_OUTBOUND_RELAY_ADDR=smtp.example.com:465
OCTO_MAIL_OUTBOUND_RELAY_USERNAME=...
OCTO_MAIL_OUTBOUND_RELAY_PASSWORD=...
```

Startup validation enforces all-or-none configuration, a valid DNS hostname,
port 465, and no simultaneous egress IP pool. The password is preserved byte for
byte and never logged.

## Delivery path

Direct mode continues to use `SourceIPDialer(resolveMX, pickSource)`, recipient
MTA-STS, DANE/TLSA, and opportunistic STARTTLS.

Relay mode replaces only the transport policy:

1. `RelayDialer` connects to the configured fixed address and returns its DNS
   hostname as the SMTP/TLS peer identity; it never resolves the recipient MX.
2. `SMTPDeliverer` invokes mox `smtpclient` with `TLSImmediate`, strict PKIX
   verification, TLS 1.2 minimum, and a relay authentication selector.
3. Authentication requires a non-nil TLS connection state, prefers RFC 4616
   PLAIN, and falls back to LOGIN only when that is what the relay advertises.
4. Recipient MTA-STS and DANE callbacks are omitted because they describe the
   recipient MX rather than the trusted submission relay.

The existing deliverer still owns message loading, DKIM, VERP envelope
rewriting, suppression, rate limiting, SMTP transaction, result classification,
and webhook hooks. No WebAPI or queue schema changes are introduced.

## TLS downgrade prevention

The existing per-message `RequireTLS` override applies only to STARTTLS/direct
delivery. `TLSImmediate` is immutable: neither `RequireTLS=true` nor `false`
changes it, so a queued header cannot make port 465 plaintext.

## Compatibility and rollout

Relay is opt-in at the executable level so existing installations outside
Tencent Cloud are not broken. Tencent Cloud deployment configuration must set
all three values before rollout. Removing them rolls back to direct MX delivery,
which will not work where outbound TCP 25 is blocked.
