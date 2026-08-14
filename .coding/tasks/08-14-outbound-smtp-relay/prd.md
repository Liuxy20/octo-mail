# Outbound SMTP relay over implicit TLS

## Goal

Allow octo-mail deployments whose cloud provider blocks outbound TCP port 25
to deliver queued mail through a deployment-provided SMTP relay on TCP 465.

## Requirements

- Add optional outbound relay address, username, and password environment
  variables; all three must be configured together.
- Relay configuration must use a DNS hostname and TCP port 465.
- When configured, every queued outbound delivery connects to that fixed relay,
  begins TLS before reading or writing SMTP, verifies its certificate, and
  authenticates after TLS using a server-advertised PLAIN or LOGIN mechanism.
- Relay mode must not perform recipient MX, MTA-STS, DANE/TLSA, or egress-source
  selection.
- Relay mode must preserve queueing, DKIM, VERP, suppression, rate limiting,
  webhook, SMTP envelope, and delivery result behavior.
- Relay credentials must not be logged.
- A configured egress IP pool and a fixed relay are mutually exclusive.
- Existing direct MX delivery remains available when relay configuration is
  absent, for deployments where outbound TCP 25 is allowed.
- Document that Tencent Cloud deployments must configure the relay variables;
  otherwise direct MX delivery remains subject to the platform's TCP 25 block.

## Out of Scope

- Changing Agent Mail Web, CLI, plugin, draft, approval, or send interactions.
- Provisioning or operating a third-party SMTP account.
- Changing message sender addresses, DKIM keys, VERP format, queue semantics, or
  the inbound SMTP/submission listeners.
- Adding STARTTLS relay modes on ports 25 or 587.

## Acceptance Criteria

- [ ] A configured relay receives TLS as the first protocol bytes, authenticates,
  and receives MAIL FROM, RCPT TO, and DATA.
- [ ] Relay certificate hostname/CA failures stop delivery.
- [ ] Authentication is refused without TLS or without a supported mechanism.
- [ ] Per-message `RequireTLS=false` cannot downgrade implicit TLS.
- [ ] Relay mode does not invoke recipient MX, MTA-STS, DANE, or egress-pool paths.
- [ ] Partial config, non-465 ports, invalid hosts, and egress-pool conflicts fail
  startup validation.
- [ ] Empty relay config retains the existing direct MX/25 path.
- [ ] Full tests, race checks, vet, build, formatting, and new-diff lint pass.
