# Design

## Boundaries and invariants

- Public WebAPI/Admin paths and JSON shapes do not change.
- `gateway_identities.default_account_id` remains a valid Agent mailbox even
  when it reuses the owner principal.
- Space is persisted as authorization evidence on `agent_bindings`; it is not
  inferred from whichever Space happens to reference the account later.
- Account writes continue to use the existing transactional/advisory-lock
  boundaries. SQL remains parameterized and tenant/account scoped.
- Unknown Draft submission results are never automatically abandoned or
  retried.

## Gateway designation and binding lifecycle

Add `agent_bindings.space_id` idempotently in schema 11. Exchange copies the
already-approved `agent_auth_requests.space_id` into the binding. Existing rows
are backfilled from their most recent matching exchanged authorization request;
unrecoverable legacy active rows remain unusable rather than being assigned to
an arbitrary Space.

Credential authentication and automation authorization require that the bound
account is still either:

1. registered in `agent_mailbox_registrations` for `binding.space_id`, or
2. the enabled Gateway default for `binding.space_id`.

Mailbox listing and mutation join only the current Space's active binding.
Internal directory mutation methods receive `spaceID` from the already
authenticated owner context, while HTTP routes and payloads remain unchanged.

An idempotent PostgreSQL trigger on `gateway_identities` revokes credentials and
bindings for the old `(default_account_id, space_id)` when a designation is
disabled, deleted, or re-pointed. This covers the existing Admin upsert and
direct operational SQL without adding a disable endpoint. Re-enabling the same
unchanged designation does not revoke anything.

## Automatic-reply labeling

Treat RFC 3834 labeling separately from optional count-chain bookkeeping. For
every request identified as an Agent automatic reply, initialize trusted
headers with `Auto-Submitted: auto-replied`. When a positive-limit Chain exists,
add the existing signed chain tuple and final-count behavior. A zero maximum
continues to mean no count limit; it no longer disables the RFC marker.

## Draft-send claims

Expose a read-only claim lookup on the transactional Draft-send capability.
Before user-driven replacement or deletion, check the current effective Email
id while holding the account transaction:

- any claim blocks replacement;
- a processing claim blocks authorized deletion;
- accepted internal post-send cleanup continues through the existing unchecked
  cleanup path.

The claim remains durable after an ambiguous submit. No automatic timeout is
introduced because elapsed time cannot prove that the external side effect did
not happen.

## Garbage collection

The GC CTE carries both physical row id and `COALESCE(email_id, id)` as the
effective Email id. Row-local projections (`fts`, `thread_refs`) remain keyed by
physical row id. Draft workflow rows and `draft_send_claims` are deleted by
effective Email id only when no non-expunged sibling with that identity exists.

## Substring search

Schema 16 installs `pg_trgm` and creates a GIN `gin_trgm_ops` index on
`fts.search_text`. The existing partial backfill index remains. This changes no
search semantics; it makes the existing `%term%` predicate indexable.

## Signed metadata replay bounds

Move the internal signing tuple to a new version that includes an intended
mailbox/recipient context and an absolute expiry. Verification receives the
authoritative local account/address context rather than trusting a header value.
Old tuples fail closed because accepting an unbounded legacy tuple would retain
the reported replay condition. Header names are internal transport metadata;
public API and UI contracts do not change.

For rule forwards, the signature binds the generated recipient set and expiry;
for automatic replies it binds the local Agent account identity and expiry.
Tests use an injectable/reference time where necessary to avoid sleeps.

## Compatibility, rollout, and rollback

- Schema changes are additive and idempotent. New application code is deployed
  after schema replay, as in the existing startup model.
- New bindings are fully Space-bound. Existing active bindings are backfilled
  only from matching exchanged authorization evidence; unresolved legacy rows
  fail closed and require reconnecting the Agent.
- Old signed internal metadata is rejected after rollout. It affects only
  in-flight loop/attribution metadata, not message delivery or content.
- Rolling application code back leaves additive columns/indexes/trigger in
  place. The trigger is compatible with older binding rows; the older binary
  ignores `space_id`. If a full rollback is required, remove the trigger before
  removing the column; the GIN index and extension are safe to retain.

## Out of scope

- Reclassifying Gateway default accounts or excluding owner-principal accounts.
- New human mailbox concepts, confirmation UX, public endpoints, or API fields.
- Retrying or manually overriding ambiguous external submissions.
- Fixing every advisory P2 in the review (intent mode-flip, projection drain
  throughput, gateway pre-auth buffering, config cosmetics, and unrelated
  documentation are separate work).
