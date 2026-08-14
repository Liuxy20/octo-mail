# Support virtual-hosted-style S3 addressing

## Goal

Allow octo-mail's existing S3 blob backend to work with providers such as
Tencent Cloud COS that require the bucket name in the request hostname, while
preserving the current path-style behavior by default.

## Requirements

- Reuse the existing S3 endpoint, region, bucket, credential, and prefix
  configuration. Do not add provider-specific COS configuration.
- Add `OCTO_MAIL_S3_FORCE_PATH_STYLE`, defaulting to `1` for backward
  compatibility. When set to `0`, object requests use virtual-hosted-style
  addressing.
- Use one shared object-URL construction path for the startup probe, PUT, HEAD,
  GET, ranged GET, and DELETE operations.
- Preserve object keys, prefix normalization, SigV4 behavior, bucket
  provisioning policy, and all non-S3 behavior.
- Document both addressing modes and a Tencent Cloud COS configuration example.

## Out of Scope

- Adding an S3 SDK or Tencent-specific client/configuration.
- Changing blob references, object-key layout, prefix migration behavior, IAM
  policy, or mail business logic.
- Auto-detecting an S3 provider from its endpoint.

## Acceptance Criteria

- [ ] `OCTO_MAIL_S3_FORCE_PATH_STYLE` is `1` by default and `0` selects
  virtual-hosted-style requests.
- [ ] Path style builds `https://endpoint/bucket/key`; virtual-hosted style
  builds `https://bucket.endpoint/key`, preserving an endpoint port and the
  configured object prefix.
- [ ] The startup probe and every blob operation use the shared URL builder.
- [ ] Existing path-style MinIO integration tests remain unchanged and pass.
- [ ] `make fmt`, `make vet`, and `make test` pass.

## Related

- https://github.com/Mininglamp-OSS/octo-mail/issues/51
