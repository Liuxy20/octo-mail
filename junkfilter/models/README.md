# Shared junk model release input

Internal release builds place `shared-junk-v1.csv.gz` in this directory before
building `octo-mail`. The Go binary embeds the package and imports it into an
empty shared-model database on first startup.

The package is generated offline with:

```text
octo-mail junk export-global <version> junkfilter/models/shared-junk-v1.csv.gz
```

Only aggregate, SHA-256-hashed feature counters are included. Raw training
messages are never copied into this directory, the binary, or the runtime image.
The generated package is intentionally ignored by Git.
