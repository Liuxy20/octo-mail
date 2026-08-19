# Allow explicit CLI draft operations

## Goal

Allow an authenticated Agent Mail CLI credential to explicitly update, send,
and delete drafts that were created as Agent drafts.

## Requirements

- Agent credentials may update, send, and delete only drafts carrying existing
  Agent-draft metadata.
- Owner-created, policy-created, and unmarked drafts remain unavailable to Agent
  credentials.
- Update and send require the current draft version and retain existing conflict,
  idempotency, and unknown-result protections.
- Explicit CLI draft operations do not depend on the mailbox automation mode and
  do not use the retired confirmation-token flow.
- Owner behavior and all non-draft Agent Mail operations remain unchanged.
- Expose only `mail draft update`, `mail draft send`, and `mail draft delete` in
  octo-cli; keep `create-agent` as the creation command.

## Acceptance Criteria

- [x] Agent update of an Agent draft succeeds and advances its version; a stale
  version returns `draft_version_conflict`.
- [x] Agent send/delete of an Agent draft succeeds through the existing WebAPI
  routes without automation or confirmation headers.
- [x] The same operations against non-Agent drafts still return `owner_required`.
- [x] octo-cli registers the three commands with the existing paths and
  `x-octo-retry: never`, without adding confirmation headers.
- [x] The Mail Skill documents the explicit-operation safety boundary and latest
  `draftId`/`draftVersion` requirement.
- [x] octo-mail and octo-cli repository quality gates pass.

## Out of Scope

- Web, octo-server, and OpenClaw plugin changes.
- New endpoints, database tables, or credential types.
- Restoring owner confirmation tokens or changing background automation behavior.
- Allowing Agent credentials to operate on Owner/policy/unmarked drafts.
