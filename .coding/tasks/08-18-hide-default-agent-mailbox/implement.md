# Implementation Plan

1. Add failing backend tests for post-provisioning Agent mailbox visibility,
   limits, default-account authorization denial, browser authentication, and
   legacy binding revocation.
2. Replace gateway-default OR conditions in Agent-only paths with the existing
   registration relation; leave browser gateway selection unchanged.
3. Add the idempotent binding-revocation migration and update comments/docs.
4. Update OCTO Web tests to pin the empty and explicitly-created mailbox
   behavior; change production code only where current assumptions require it.
5. Run backend live PostgreSQL/MinIO tests plus frontend package tests,
   typecheck, lint, and build. Review both diffs for scope drift.
