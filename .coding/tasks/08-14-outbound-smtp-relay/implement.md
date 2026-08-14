# Implementation Plan

1. Add relay environment configuration, fail-fast validation, examples, and
   Tencent Cloud deployment guidance.
2. Add a fixed-address relay dialer and TLS-only PLAIN/LOGIN authentication
   selector using the vendored mox protocol implementation.
3. Extend `SMTPDeliverer` with narrow TLS/auth options and make implicit TLS
   immune to the existing per-message STARTTLS override.
4. Select either the existing direct-MX transport or the relay transport in the
   composition root without changing higher-level delivery hooks.
5. Add configuration, dialer, TLS, certificate, authentication, SMTP transaction,
   and policy-bypass regression tests.
6. Run focused race tests, serial full tests with PostgreSQL/MinIO, vet, static
   build, gofmt, diff checks, and golangci-lint on the branch diff.
