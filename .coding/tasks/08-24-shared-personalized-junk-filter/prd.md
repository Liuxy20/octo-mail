# Shared Junk Baseline and Mailbox Sender Allowlist

## Goal

Ship a useful shared Bayesian junk baseline without account-local content
training. Content and sender-reputation spam signals may file mail into Junk,
but must not reject or delete it. Owners can restore a message from Junk and
explicitly trust that exact sender for the current mailbox.

## Requirements

- The shared model belongs to the Octo Mail deployment and is imported from a
  reviewed aggregate model package on first startup.
- Inbound Bayesian classification uses only the shared model. Marking or
  unmarking Junk must not train account-local word statistics.
- Keep Mox MIME parsing/tokenization and the existing bounded CJK features.
- Bayesian and sender-reputation junk decisions may only deliver to Junk. They
  must never produce an SMTP rejection or delete a message.
- Existing protocol/security hard failures, including configured DMARC and
  DNSBL enforcement, remain unchanged.
- Each mailbox account has an explicit exact-address sender allowlist. It is
  isolated by account ID and never shared across mailboxes.
- An allowlisted sender bypasses content/reputation Junk routing only when the
  visible From identity passes DMARC alignment. An unauthenticated spoof of an
  allowlisted address receives no bypass.
- The owner-only "not junk" action removes `$Junk` and adds the stored message's
  exact From address to that mailbox's allowlist.
- Classification/storage failures fail open to normal delivery rather than
  losing mail.

## Out of Scope

- Per-account Bayesian training, feedback ledgers, model blending, or online
  learning from mailbox moves.
- A sender blocklist, domain-wide allowlist, contact import, or organization-
  wide allowlist.
- Embedding Spam Scanner, Rspamd, Redis, a GPU, an LLM, or a separate service.
- Changing SPF, DKIM, DMARC, or DNSBL implementations and enforcement.
- Deleting junk mail automatically.

## Acceptance Criteria

- [ ] AC1: A fresh deployment imports the bundled aggregate model once and an
  untrained mailbox can route matching spam to Junk.
- [ ] AC2: Shared-model and known-bad-reputation outcomes never return a content
  Reject; they return `AcceptJunk`.
- [ ] AC3: Junk flag changes do not train an account-local Bayesian model.
- [ ] AC4: Restoring a Junk message through the owner WebAPI removes `$Junk` and
  adds its normalized exact From address to only that account's allowlist.
- [ ] AC5: A DMARC-authenticated allowlisted sender bypasses Junk scoring;
  unauthenticated spoofed mail with the same From address does not.
- [ ] AC6: Owners can list and remove entries for the current mailbox; Agent
  credentials cannot manage the allowlist or invoke the restore-and-trust action.
- [ ] AC7: Model package import, CJK classification, tenant isolation, WebAPI,
  SMTP routing, formatting, vet, build, and live-infrastructure tests pass.
