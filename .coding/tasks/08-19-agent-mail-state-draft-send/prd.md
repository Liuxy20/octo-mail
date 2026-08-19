# Complete Agent Mail state and draft sending

## Goal

Expose lightweight account state and enforce current outbound policy for explicitly selected Draft sends.

## Requirements

- Expose the authenticated account change-log head through a lightweight,
  non-cacheable WebAPI state endpoint.
- Allow Agent credentials to send an ordinary human-authored Draft after the
  caller has explicitly selected that Draft for sending.
- Keep explicit selection in the caller/CLI workflow; no separate confirmation
  artifact crosses the WebAPI boundary.
- Re-evaluate the current outbound policy before every Agent Draft send,
  including recipients, subject, text, HTML, and attachment count.
- When the current policy requires review, keep the message out of Sent and the
  delivery queue and create one deduplicated owner-review Draft.
- Preserve version checks for Agent-prepared Drafts and existing owner behavior.

## Acceptance Criteria

- [x] `GET /webapi/v0/state` returns the authenticated account state with
  `Cache-Control: no-store`.
- [x] An Agent credential can send an ordinary human-authored Draft without an
  Agent Draft version.
- [x] Agent-prepared Drafts continue to use their current version.
- [x] A Draft blocked by the current outbound policy is not queued or moved to
  Sent, and repeated attempts do not create duplicate review Drafts.
- [x] Protocol tests cover state changes, successful sends, and policy review.

## Out of Scope

- No new database table, credential type, or confirmation-token path.
- No change to mailbox automation modes or owner Draft behavior.
- No Web, CLI, Server, or plugin implementation in this repository.

## Related

- https://github.com/Mininglamp-OSS/octo-mail/issues/64
