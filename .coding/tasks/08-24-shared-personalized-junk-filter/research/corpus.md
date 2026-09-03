# Shared Junk Model Policy

## Scope

The deployment-wide Bayesian model provides a baseline for new mailboxes. Its
decisions may route accepted mail to Junk, but never reject or delete mail.
Runtime classification is enabled by default and can be disabled with
`OCTO_MAIL_SHARED_JUNK_ENABLED=0` without deleting model data.

## Release boundary

- A model committed to the public repository must use project-owned synthetic
  inputs or sources whose terms permit redistribution of the derived artifact.
- Required third-party attribution is recorded in `NOTICE`.
- Source message files are not included in the package. Deterministic feature
  identifiers can be enumerable for low-entropy tokens and are not a
  confidentiality control.
- Sender and recipient identity headers are excluded from deployment-wide
  training and classification.

## Evaluation gate

- The runtime threshold defaults to `0.9999` and remains configurable.
- Both classes require at least 200 learns before the model is active.
- Across the release evaluation matrix, normal-mail Junk routing must not exceed
  0.5% and Spam recall must be at least 40%.
- The short-Chinese regression must have no normal-mail misroutes and at least
  80% Spam recall.
- Representative verification, security, billing, HR, IT, collaboration, and
  delivery messages must remain in Inbox.
- Evaluation uses the same bounded classification path as production.

## Packaging

The bundled package contains aggregate Ham/Spam counters keyed by deterministic
feature identifiers. Its version, totals, feature count, and digest are pinned
by automated tests. Existing shared-model data is never overwritten.
