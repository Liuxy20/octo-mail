# Design

## Existing mechanisms reused

- `agent_outbound_drafts` metadata identifies drafts created for Agent use.
- `draftVersion` remains the optimistic concurrency token for update and send.
- `draft_send_claims` continues to provide send idempotency and unknown-result
  protection.
- The authenticated account capability continues to provide tenant/account
  isolation.
- `removeDraftAuthorized` remains the delete authorization implementation.

## Authorization change

The three draft routes use normal authenticated WebAPI handling. Their handlers
authorize Agent credentials by requiring existing Agent-draft metadata. Owner,
policy, and unmarked drafts keep their current behavior. Explicit CLI Draft
operations do not use the automation-mode or owner-confirmed-draft branches.
Those legacy branches are outside this task and remain unchanged.

## CLI exposure

The metadata registry exposes PATCH/POST/DELETE operations for update, send, and
delete. No custom client code, request header, or backend contract is added.

## Compatibility

Owner behavior, message send-intent behavior, background plugin automation, and
all public request/response shapes remain unchanged.
