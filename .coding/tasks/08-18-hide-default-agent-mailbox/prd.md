# Hide gateway default account from Agent Mail

## Goal

Keep the gateway-provisioned default mailbox as an internal browser account,
while exposing and authorizing only explicitly registered Agent mailboxes.

## Requirements

- Do not change gateway first-use provisioning or octo-server integration.
- The gateway default account must not be listed, counted, deleted, configured,
  or approved as an Agent mailbox.
- Only `agent_mailbox_registrations` records establish Agent mailbox ownership
  in a Space.
- Browser gateway authentication must continue to use the default account when
  no mailbox is selected and may select registered Agent mailboxes explicitly.
- Existing active Agent bindings against a gateway default account must be
  revoked without deleting the account, address, Inbox, or stored mail.
- OCTO Web must show only explicitly created Agent mailboxes and retain the
  existing empty/create/connection interaction.

## Acceptance Criteria

- [x] Gateway provisioning still creates and reuses its default account and Inbox.
- [x] A freshly provisioned owner sees zero Agent mailboxes and can create the
  configured number of independent Agent mailboxes.
- [x] The gateway default account cannot be approved for Agent authorization or
  used by an Agent credential.
- [x] Existing default-account Agent bindings are revoked by an idempotent schema
  migration without deleting mailbox data.
- [x] Browser gateway authentication still resolves the default account and
  registered Agent mailbox selection correctly.
- [x] OCTO Web management, switching, and authorization surfaces contain no
  gateway default account.
- [x] Backend and frontend quality gates pass.

## Out of Scope

- Removing or redesigning gateway provisioning.
- Changing default mailbox address generation or deleting its data.
- octo-server, octo-cli, or OpenClaw plugin changes.
- New mailbox-management interactions or visual redesign.
