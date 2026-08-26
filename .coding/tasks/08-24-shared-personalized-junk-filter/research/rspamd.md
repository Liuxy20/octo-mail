# Rspamd Research Summary (2026-08-24)

## Official Sources

- Statistics configuration: https://rspamd.com/doc/configuration/statistic.html
- Actions and thresholds: https://rspamd.com/doc/configuration/metrics.html

## Relevant Findings

- Rspamd supports shared Bayesian classifiers alongside `per_user` classifiers; shared data does not belong to a synthetic admin tenant.
- Its documented default `min_learns=200` prevents a classifier with too little data from driving decisions.
- Its learning flow includes learned-ID deduplication, class balancing, and protection against relearning an already-known class.
- Rspamd uses OSB and inverse chi-square; OSB windowing expands token volume substantially.
- Rspamd maps weighted detection symbols to actions, keeping classification signals separate from delivery actions.

## Octo Mail Tradeoffs

- Do not copy the full OSB/Redis/rules stack; retain the existing Mox tokenizer and Bayesian calculation.
- Adopt a shared baseline, minimum class counts, exact-address owner allowlists,
  and conservative actions.
- Add only bounded CJK bigram/trigram features to avoid OSB-scale storage growth.
- A shared-model content result may route to Junk but cannot cause permanent
  rejection. Runtime mailbox actions do not train account-local word models.
