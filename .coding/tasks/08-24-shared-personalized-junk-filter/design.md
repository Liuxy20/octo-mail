# Design: Shared Junk Baseline and Mailbox Sender Allowlist

## Classification

The existing Mox tokenizer and bounded CJK features feed one deployment-wide
Bayesian model. Runtime classification does not read or update per-account word
statistics. The model is an aggregate release artifact and stores no raw mail.

The action policy is deliberately reversible:

1. Configured DMARC/DNSBL protocol hard failures remain unchanged.
2. A DMARC-authenticated exact sender in the recipient account's allowlist is
   delivered normally.
3. Existing sender reputation and the shared Bayesian model may route to Junk.
4. Neither content nor reputation deletes or permanently rejects mail.

## Mailbox Sender Allowlist

Store normalized exact addresses in a hash-partitioned
`junk_sender_allowlist(account_id, sender_address, created_at)` table. The
account ID is the first primary-key column, preserving structural isolation.

The allowlist is deliberately exact-address only. Domain-wide trust has a much
larger blast radius and is outside this version.

SMTP checks an entry only when DMARC reports a pass for the visible From domain.
This prevents an attacker from spoofing a trusted From address to bypass content
classification.

## Owner Feedback Surface

Add owner-only WebAPI operations to:

- restore one stored Junk message and trust its parsed From address;
- list the current account's trusted senders;
- remove one trusted sender.

The restore operation derives the sender from immutable stored message bytes,
not from client input. The Junk flag update and allowlist insertion use the same
account transaction through an optional core-store transaction capability.

IMAP/JMAP Junk moves remain mailbox organization operations. They no longer
train a personal model and do not implicitly trust a sender.

## Compatibility

Existing `junk_words`, `junk_totals`, and old feedback rows may remain in an
upgraded database but are no longer consulted by inbound classification. This
avoids destructive migration work and permits rollback to an older binary.

SubjectPass is removed from this decision path because content and reputation
signals no longer reject mail.
