# Agent Mail automatic owner provisioning

## Goal

Allow octo-server to idempotently provision the authenticated OCTO user and
Space before proxying the user's first browser Mail request, removing the need
for per-user manual Admin API calls.

## Requirements

- Add a narrow internal provisioning endpoint authenticated by the existing
  request-bound `OCTO_MAIL_GATEWAY_SECRET` assertion.
- Derive issuer, subject, and Space exclusively from the verified assertion.
- Accept only a preferred localpart as provisioning input; tenant, domain,
  principal, account, and address IDs are never caller supplied.
- Resolve the tenant through the configured `OCTO_MAIL_AGENT_MAILBOX_DOMAIN`,
  which remains deployment-provisioned.
- In one PostgreSQL transaction, reuse a compatible existing owner account or
  create its principal, account, primary address, Inbox, and exact gateway
  identity binding.
- Serialize concurrent provisioning and make retries return the same account.
- Preserve disabled gateway identities as disabled; automatic provisioning must
  not undo an operator revocation.
- Keep the existing Admin API and all WebAPI business contracts unchanged.

## Out of Scope

- Creating deployment-level tenants or domains from a browser request.
- Changing messages, drafts, Agent authorization, or Agent mailbox behavior.
- Changing frontend, CLI, or OpenClaw plugin interactions.

## Acceptance Criteria

- [ ] AC1: a fresh subject and Space under a pre-provisioned domain receive one
  owner principal, account, primary address, Inbox, and gateway binding.
- [ ] AC2: repeated and concurrent ensure calls return the same account without
  duplicate rows.
- [ ] AC3: an existing manually provisioned exact gateway identity is returned
  unchanged rather than creating another account.
- [ ] AC4: a disabled binding, missing configured domain, invalid localpart, or
  conflicting owner fails closed without partial writes.
- [ ] AC5: unsigned, tampered, expired, or replayed internal requests are refused.
- [ ] AC6: existing gateway authentication and tenant/Space isolation tests pass.
- [ ] AC7: `make fmt`, `make vet`, `make test`, and `golangci-lint run ./...` pass
  against the required test infrastructure.
