# Add configurable S3 prefix path

## Goal

Allow one S3 bucket to be safely partitioned by a deployment-configured object-key prefix without changing the existing default object layout.

## Requirements

- Add an optional `OCTO_MAIL_S3_PREFIX_PATH` environment variable and expose it in the repository's documented/container configuration surfaces.
- When configured, prepend the normalized prefix to every S3 blob object key. Bucket existence checks and bucket creation must continue to target the bucket root.
- Empty configuration must preserve the existing `<tenant>/<ab>/<cd>/<sha256>` object-key layout byte-for-byte.
- Accept a conventional slash-delimited prefix with optional leading/trailing slashes, while failing startup on ambiguous or unsafe path forms instead of silently rewriting them.
- The prefix affects only the S3 backend; local filesystem storage remains unchanged.
- Document that changing the prefix does not migrate existing objects and can make previously stored message bodies unreachable until the objects are moved.
- Do not change blob references, database schemas, mail protocol behavior, or external backend interfaces.

## Acceptance Criteria

- [x] AC1 (executable): `go test ./storage/blob ./cmd/octo-mail -count=1` → prefix normalization, key generation, bucket-root behavior, and env loading tests pass.
- [x] AC2: With no prefix configured, generated object keys exactly match the pre-change layout.
- [x] AC3: With `OCTO_MAIL_S3_PREFIX_PATH=/mail/prod/`, all blob object operations use `mail/prod/<tenant>/<ab>/<cd>/<sha256>`.
- [x] AC4: `.env.example`, `docker-compose.yml`, and `README.md` expose and explain the new setting and its migration caveat.
- [x] AC5 (executable): `go test -p 1 ./...` → the repository test suite passes against its required PostgreSQL/MinIO services.

## Notes

- Defaulting the prefix to a non-empty value would be a breaking storage migration and is explicitly out of scope.
- Automatic migration and dual-read fallback are out of scope.
