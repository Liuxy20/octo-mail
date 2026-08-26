# Verification: Shared Junk Baseline and Sender Allowlist

Date: 2026-08-25

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

- Version: `2026-08-26-v2`
- Compressed size: 2.5 MiB
- Training totals: 625 Ham / 1,259 Spam
- Features: 76,438 SHA-256 identifiers; raw messages are not packaged
- Package SHA-256:
  `42ec9fe41331a1357cbff75cde2a9628189054525461437b557ce75e1ce9a086`
- Original frozen evaluation at threshold `0.9999`: 0/420 Ham false positives
  and 387/420 Spam detected (92.14%).
- Short-Chinese regression evaluation: 0/20 collaboration Ham false positives
  and 18/20 Spam detected. The reported short meeting example is classified as
  Ham.
- Expanded stress evaluation: 0/920 Ham false positives and 785/993 Spam
  detected (79.05%).

The generated model is an ignored internal release input at
`junkfilter/models/shared-junk-v1.csv.gz`; a release build must place it in the
build context before compiling.

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
