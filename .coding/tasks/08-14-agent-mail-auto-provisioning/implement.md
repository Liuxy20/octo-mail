# Implementation Plan

1. Extend the core directory contract with an internal gateway provisioning
   input/result and branchable sentinel errors.
2. Implement the PostgreSQL transaction, reuse rules, deterministic collision
   fallback, Inbox initialization, and concurrency tests.
3. Add the HMAC-authenticated internal HTTP handler and mount it from the
   composition root.
4. Add handler tests for valid, tampered, expired, replayed, and failure cases.
5. Run formatting, focused tests, the serial full suite, vet, build, and
   golangci-lint; verify no frontend or business API drift.
