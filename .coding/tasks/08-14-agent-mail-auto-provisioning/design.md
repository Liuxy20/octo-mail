# Design

## Boundary

The internal endpoint is mounted on the same HTTP service as WebAPI but outside
`/webapi/v0`, so the browser gateway cannot proxy to it. It verifies the same
short-lived, method/URI/body-bound HMAC assertion already used for browser mail
requests and consumes its nonce through the existing replay store.

Request body:

```json
{"localpart":"guobin"}
```

Issuer, subject, and Space come only from signed claims. The configured Agent
mailbox domain selects the tenant because a domain belongs to exactly one
tenant.

## Storage transaction

1. Begin a transaction and lock the configured domain row to serialize rare
   first-use provisioning.
2. Re-read the exact `(issuer, subject, space_id)` gateway identity.
3. Return an active mapping unchanged; reject a disabled mapping.
4. Return an existing exact manually provisioned binding unchanged; otherwise
   allocate an address that is unique to this subject and Space.
5. Otherwise create principal, account, primary address, and Inbox.
6. Insert the exact gateway identity and commit.

Address conflicts use a deterministic subject-and-Space-derived suffix so two
valid OCTO users, or the same user in two Spaces, remain isolated and
provisionable without exposing database identifiers to octo-server.

## Reuse decisions

- Reuse `security/gatewayassert` for request-bound HMAC verification instead of
  defining a second service-token format.
- Reuse `GatewayAssertionReplayDirectory` and the existing PostgreSQL nonce
  table instead of adding another replay cache.
- Reuse the existing configured `OCTO_MAIL_AGENT_MAILBOX_DOMAIN` as the single
  domain/tenant source of truth instead of adding duplicate tenant/domain
  configuration.
- Reuse the existing `pgTx.ensureMailbox` + `flush` path used by
  `CreateAgentMailbox`, so the initial Inbox and changelog stay consistent.
- Follow the existing `CreateAgentMailbox` principal/account/address creation
  invariants and `AuthenticateGatewayIdentity` exact binding semantics.

The generic Admin handlers are intentionally not called from octo-server: they
are separate non-idempotent operations guarded by an over-broad Admin token and
cannot provide one atomic retry-safe user initialization. `CreateAgentMailbox`
also cannot be called directly because it requires an already provisioned human
owner and source account. The new code therefore composes the existing storage
primitives behind one narrow transaction rather than reproducing the Admin API
workflow.

## Compatibility

- No schema change is expected; existing uniqueness constraints and a row lock
  provide concurrency safety.
- Existing Admin provisioning remains available.
- Existing `/webapi/v0` requests and responses are unchanged.
- Existing manually provisioned gateway identities are returned as-is.

## Rollback

Disabling the octo-server provisioning call restores the old explicit
provisioning behavior. The internal endpoint creates ordinary existing directory
rows, so no data migration or rollback conversion is required.
