# Design

## Ownership boundary

`gateway_identities.default_account_id` remains the browser gateway's internal
default account. It is not Agent authorization evidence. Only an
`agent_mailbox_registrations` row with the exact owner and Space makes an account
an Agent mailbox.

All Agent mailbox listing, limits, management, approval, credential
authentication, and automation checks use that single registration boundary.
Browser gateway authentication is unchanged: no selected account resolves the
gateway default, while a selected account must be either that default or a
registered Agent mailbox.

## Existing bindings

An idempotent schema migration revokes active bindings and credentials whose
account is an active gateway default, even if legacy data also contains a
registration. It does not mutate accounts, addresses, mailboxes, or messages.

## Frontend

The existing `/agent-mailboxes` contract continues to return `mailboxes`, but
the backend collection now contains only explicitly registered Agent mailboxes.
The current empty state, create flow, switcher, and authorization picker consume
that corrected collection without a new UI surface.
