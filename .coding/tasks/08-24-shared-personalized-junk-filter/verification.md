# Verification: Shared Junk Baseline and Sender Allowlist

Date: 2026-09-03

## Scope verified

- A deployment-wide Bayesian model is imported transactionally into an empty
  database and reused by every account and server node.
- Runtime IMAP flag changes do not write account-local Bayesian training data.
- Shared content scores and known-bad sender reputation only route accepted mail
  to Junk; they do not issue SMTP rejection or SubjectPass challenges.
- Restoring a Junk message moves it to Inbox, marks it NotJunk, and adds the
  normalized exact From address to that account's allowlist.
- Allowlist operations are account-scoped and human-owner-only.
- An allowlist match bypasses Junk routing only when the visible From identity
  passes DMARC; an unauthenticated spoof with the same address still goes to
  Junk.

## Bundled model

- Version: `2026-09-03-v4`
- Compressed size: 3.1 MiB
- Training totals: 7,212 Ham / 7,960 Spam
- Features: 83,235 deterministic SHA-256 identifiers
- Package SHA-256:
  `5629bc3b5ddb81c499a6f16eed8f53741097d8b2369b970ee09146ec92e50bfe`
- De-duplicated evaluation matrix at threshold `0.9999`: 2/1,488 Ham false
  positives (0.13%) and 1,071/1,971 Spam detected (54.34%).
- Short-Chinese regression: 0/20 Ham false positives and 19/20 Spam detected
  (95%).
- The bundled regression panel keeps representative Chinese and English
  verification, security, billing, HR, IT, collaboration, and delivery mail in
  Inbox while routing the representative Chinese and English Spam cases to
  Junk.
- CJK header-padding regressions: body signals survive distinct identity-header
  and folded Subject padding. Per-token feature limits also preserve body
  signals under plain-text and hidden-HTML CJK padding.

The model is bundled at `junkfilter/models/shared-junk-v1.csv.gz` and imported
only when deployment-wide model storage is empty.

## Commands

- `make fmt` — passed.
- `make vet` — passed.
- `make build` — passed after supplying the existing local TypeScript compiler
  on `PATH`.
- `go test -p 1 ./mailflow/inbound ./junkfilter ./protocol/imapd ./protocol/smtpd ./protocol/webapi ./cmd/octo-mail` — passed against live PostgreSQL.
- `OCTO_MAIL_S3_SECRET=<local-test-secret> go test -p 1 ./...` — passed against
  live PostgreSQL and MinIO. The environment override matches the credentials
  of the existing local `octo-minio-1` container.
- Octo Web focused Vitest suite — 38 tests passed.
- Octo Web `pnpm i18n:check` and `pnpm --filter @octo/mail typecheck` — passed.
