# Implementation Plan

1. Simplify the classifier to use only the deployment-wide aggregate model and
   remove runtime personal-feedback integration from IMAP, JMAP, and WebAPI.
2. Change Bayesian and sender-reputation content outcomes to `AcceptJunk` only;
   preserve configured DMARC/DNSBL hard rejection.
3. Add the account-partitioned exact-sender allowlist and account-scoped storage
   transaction capability.
4. Add owner WebAPI routes for restore-and-trust, list, and remove operations.
5. Gate SMTP allowlist bypass on a DMARC pass for the visible From identity.
6. Update model tooling/docs and add regression tests for isolation, spoof
   resistance, no-reject behavior, and no personal training.
7. Add the Octo Web Junk-detail action and confirmation flow, then refresh list
   and mailbox counts after success. Add a compact allowlist management surface
   only if it can reuse the existing mail settings entry without a second
   overlapping navigation path.
8. Run backend format/vet/build/live-infrastructure tests and frontend focused
   tests/typecheck/i18n checks.

## Rollback

- Disable shared-model loading to return to neutral content classification.
- Leave allowlist rows in place; an older binary ignores the additive table.
- Revert the Web action independently if the backend is not yet deployed.
