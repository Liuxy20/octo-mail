# Shared junk model

`shared-junk-v1.csv.gz` is the default deployment-wide model bundled with
`octo-mail`. When shared classification is enabled, the binary imports it into
an empty shared-model database on startup. Existing model data is not replaced.

The package is generated offline with:

```text
octo-mail junk export-global <version> /tmp/shared-junk-model.csv.gz
```

The package contains aggregate, deterministically hashed feature counters. The
hashes are identifiers, not a confidentiality boundary. Raw messages are not
part of the package; source attribution is recorded in the repository NOTICE.
Other generated model packages in this directory remain ignored by Git.
