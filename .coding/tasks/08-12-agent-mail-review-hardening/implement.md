# Implementation plan

1. Add regression tests for zero-limit automatic-reply labeling and separate
   RFC labeling from optional chain metadata.
2. Add `space_id` persistence/backfill, Space-scoped binding projections and
   mutations, credential eligibility re-checks, and Gateway designation
   revocation propagation. Verify the owner-principal default mailbox remains
   supported.
3. Add transactional Draft-send claim lookup and block user-driven edit/delete
   bypasses without touching accepted-send internal cleanup.
4. Correct GC effective-Email identity handling, include Draft-send claims, and
   add a live-sibling regression.
5. Add the `pg_trgm` extension/index migration and verify its schema/query-plan
   presence with PostgreSQL tests where available.
6. Version signed auto-reply/rule metadata with account/recipient context and
   expiry, update all call sites, and cover valid, cross-context, and expired
   verification.
7. Run targeted package/integration tests after each batch. Then run
   `make fmt`, `make vet`, `make build`, and `make test` with real PostgreSQL and
   MinIO; confirm no required integration suite was skipped.
8. Review the final diff against the PRD, injected specs, and dirty-worktree
   boundary. Do not stage, commit, or push until the user requests that phase.

## Rollback points

- Batch 1 is code/test only and can be reverted independently.
- Batch 2's application changes depend on additive `space_id`; retain the
  column during binary rollback. Remove the revocation trigger first only if
  designation propagation itself must be rolled back.
- Batches 3 and 4 share Draft identity semantics and should be reverted
  together.
- The trigram index may be dropped independently without changing results.
- Signed-metadata version changes should be reverted atomically across sign and
  verify call sites.

## Review gates

- No `principal_id <> owner_principal_id` predicate is introduced.
- No HTTP route, JSON model, owner-facing copy, or confirmation phrase changes.
- All credential queries are account/tenant/Space scoped and fail closed.
- No elapsed-time cleanup converts an unknown submission into retryable state.
- GC never deletes effective-Email workflow state while any live sibling
  remains.
