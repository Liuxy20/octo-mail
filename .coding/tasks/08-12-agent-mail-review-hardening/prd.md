# Harden Agent Mail review findings without product changes

## Goal

Close the verified authorization-lifecycle, loop-suppression, Draft idempotency,
garbage-collection, signed-metadata, and substring-search gaps reported against
PR #48 without changing the established product model, public API payloads, or
owner/Agent interaction.

The current product has Agent mailboxes only. A Gateway default account is an
administrator-designated initial Agent mailbox and may intentionally reuse the
owner principal/login. This task must preserve that behavior.

## Requirements

- Preserve Gateway-default Agent mailbox authorization even when
  `account.principal_id == account.owner_principal_id`; do not add a
  principal-inequality eligibility rule.
- Bind every newly exchanged Agent credential to the authorization request's
  Space and re-check that the account remains designated or registered in that
  Space on credential use.
- Revoking, disabling, or re-pointing a Gateway designation must invalidate
  active credentials issued for the former account/Space without requiring a
  new public endpoint or UI action.
- An Agent automatic reply must always carry `Auto-Submitted: auto-replied`,
  including the documented configuration where the reply-count limit is zero.
- An unresolved Draft-send claim must continue to block edits and owner
  deletion of the same effective Email so replacing the Draft cannot evade the
  unknown-result guard. Accepted-send cleanup must remain functional.
- GC must delete workflow metadata by effective Email identity only when no
  live sibling remains, and must include orphaned Draft-send claims.
- Completed substring-search backfills must use an index suitable for leading
  wildcard `ILIKE` queries.
- Server-authenticated automatic-reply and rule-forward metadata must bind its
  intended mailbox/recipient context and a bounded validity window so captured
  metadata cannot be replayed indefinitely or against a different mailbox.
- Preserve current route names, JSON request/response shapes, Chinese owner
  confirmation interaction, mailbox model, outbound-mode semantics, and SMTP,
  IMAP, JMAP, and WebAPI behavior outside the corrected failure cases.
- Do not mix or overwrite unrelated dirty workspace files.

## Acceptance Criteria

- [x] Gateway-default accounts that reuse the owner principal still authorize
      successfully in their designated Space.
- [x] A binding created in Space A is not projected, mutated, revoked, or
      authenticated as a Space B binding; disabling/re-pointing the Space A
      designation invalidates its old credential.
- [x] With `OCTO_MAIL_AUTO_REPLY_MAX_COUNT=0`, an Agent automatic reply is sent
      with `Auto-Submitted: auto-replied`; existing positive-limit chain tests
      retain their behavior.
- [x] A processing or accepted claim prevents user-driven Draft replacement;
      a processing claim prevents user-driven Draft deletion; an accepted send
      can still perform its internal Draft cleanup.
- [x] GC keeps policy/Agent Draft metadata and send claims while a live sibling
      shares the effective Email id, and removes them after the last row is
      expunged.
- [x] PostgreSQL has a `pg_trgm` GIN index usable by the substring-search
      predicate after `search_text` backfill.
- [x] Signed metadata from one mailbox or an expired validity window fails
      verification; valid current metadata continues to work.
- [x] Targeted regression tests pass against real PostgreSQL, and `make fmt`,
      `make vet`, `make build`, and `make test` pass with required services.
- [x] Final diff contains only task-owned implementation, migration, test, and
      Coding-task files; unrelated local notes remain untouched.

## Notes

- The Gateway-default mailbox question is settled for this task: it is an Agent
  mailbox. Isolation is enforced through explicit designation/registration and
  Space-bound credential lifecycle, not through principal inequality.
- Unknown external submission outcomes remain fail-closed and non-retryable.
  This task does not add an operator/UI override that could authorize a second
  delivery.
