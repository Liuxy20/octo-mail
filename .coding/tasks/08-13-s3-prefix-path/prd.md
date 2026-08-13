# Add configurable S3 prefix path

## Goal

Allow one S3 bucket to be safely partitioned by a deployment-configured object-key prefix without changing the existing default object layout.

## Requirements

- Add an optional `OCTO_MAIL_S3_PREFIX_PATH` environment variable and expose it in the repository's documented/container configuration surfaces.
- When configured, prepend the normalized prefix to every S3 blob object key.
- Treat `OCTO_MAIL_S3_BUCKET` as the name of a pre-provisioned bucket. Application startup must not issue bucket-level existence probes or bucket-creation requests; deployment infrastructure owns bucket provisioning. Fail startup on endpoint, credential, bucket, or prefix-level permission errors by issuing a read-only GET for an absent sentinel object under the configured prefix; only `NoSuchKey` (or a successful GET) passes the probe.
- Empty configuration must preserve the existing `<tenant>/<ab>/<cd>/<sha256>` object-key layout byte-for-byte.
- Accept a conventional slash-delimited prefix with any number of optional leading/trailing slashes. After removing those outer slashes, allow only `[A-Za-z0-9._-]+` in each non-empty segment; fail startup on every other character or unsafe path form.
- The prefix affects only the S3 backend; local filesystem storage remains unchanged.
- Document that changing the prefix is an offline storage migration: all writers and projection workers must stop, all nodes must switch together without a mixed-prefix rolling window, and objects must be moved before traffic resumes. Warn that an incorrect/mixed-prefix projection window can permanently clear summary/search metadata for not-yet-folded messages and that restoring the prefix or objects does not automatically repair it.
- Do not change blob references, database schemas, mail protocol behavior, or external backend interfaces.

## Acceptance Criteria

- [x] AC1 (executable): `go test ./storage/blob ./cmd/octo-mail -count=1` → the per-segment allowlist (including rejection of every known wire/SigV4-divergent character), prefix normalization, key generation, read-only object-level startup probe, no bucket-level startup requests, and env loading tests pass.
- [x] AC2: With no prefix configured, generated object keys exactly match the pre-change layout.
- [x] AC3: With `OCTO_MAIL_S3_PREFIX_PATH=/mail/prod/`, all blob object operations use `mail/prod/<tenant>/<ab>/<cd>/<sha256>`.
- [x] AC4: `.env.example`, `docker-compose.yml`, and `README.md` expose and explain the new setting, coordinated offline migration procedure, mixed-prefix prohibition, and irreversible summary/search metadata risk.
- [x] AC5 (executable): `go test -p 1 ./...` → the repository test suite passes against its required PostgreSQL/MinIO services.
- [x] AC6: The real-MinIO blob and PostgreSQL S3 integration tests exercise both the legacy empty-prefix layout and a configured-prefix layout; only an unreachable S3 endpoint is skipped.

## Notes

- Defaulting the prefix to a non-empty value would be a breaking storage migration and is explicitly out of scope.
- Automatic migration and dual-read fallback are out of scope.
- Automatic bucket creation is out of scope. Local and CI environments must provision their test bucket before starting octo-mail.
