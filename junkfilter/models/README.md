# Default shared junk model

`shared-junk-v1.csv.gz` is the versioned default Bayesian model used to
bootstrap shared junk-mail classification. The Go binary embeds the package and
imports it transactionally when the shared-model database is empty. Existing
model data is never overwritten.

The model is generated from reviewed multilingual email corpora and contains
only aggregate SHA-256 feature statistics. Raw messages and attachments are not
included.

## Release metadata

- Model version: `2026-08-26-v2`
- Ham samples: `625`
- Spam samples: `1259`
- Features: `76438`
- SHA-256: `42ec9fe41331a1357cbff75cde2a9628189054525461437b557ce75e1ce9a086`

## Regeneration

After training and evaluation, export a compatible package with:

```text
octo-mail junk export-global <version> junkfilter/models/shared-junk-v1.csv.gz
```
