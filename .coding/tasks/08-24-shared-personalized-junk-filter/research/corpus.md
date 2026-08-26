# Shared Junk Corpus Plan (2026-08-25)

## Decision

Do not ship a shared classifier trained mainly from a convenient public CSV.
The production corpus must be a reproducible, reviewed RFC 5322 dataset whose
holdout set reflects Octo Mail's actual Chinese/English traffic.

Target set:

| Split | Ham | Spam |
|---|---:|---:|
| Train | 5,000 | 5,000 |
| Evaluation | 1,500 | 1,500 |

Initial language mix is 60% Chinese, 30% English, and 10% mixed-language. Ham
must deliberately include verification/security messages, human collaboration,
legitimate marketing/newsletters, and Octo Bot/system notifications. Spam must
include recent Chinese/English spam, phishing, short-link and HTML campaigns.

## Public-source findings

- [SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)
  is an official RFC 5322 corpus, but its 2002–2005 content is only suitable as a
  small legacy/hard-ham supplement. The corpus README also says not to deliver
  its messages through a real mail system and notes that message copyright stays
  with the original authors.
- [NIST TREC Spam Track](https://trec.nist.gov/data/spam.html) documents several
  historical corpora, including Chinese TREC06C, but the original TREC06C
  download was unavailable during this work. Unofficial mirrors without a clear
  dataset license are not accepted as production inputs.
- [CMU Enron](https://www.cs.cmu.edu/~enron/) is large but old, privacy-sensitive,
  attachment-incomplete, and badly mismatched to verification/notification mail.
- Many current Hugging Face “spam email” datasets are CSV repackagings of those
  corpora, SMS data, or synthetic LLM text. They do not preserve RFC 5322/MIME and
  their provenance is often incomplete, so they are not used to manufacture a
  production result.
- [cw-l/email-corpus](https://github.com/cw-l/email-corpus) is a useful modern
  MIT-licensed supplement: 1,108 redacted real-world Spam/Phishing `.eml` samples.
  Audit found only 440 content-template clusters (one cluster contains 642
  messages), leaving 485 samples after the 20-per-template cap; all are English.
- [PhishMMF](https://github.com/12345677876/PhishMMF) includes a Datacon2023
  Chinese phishing subset. It provides 2,992 convertible samples and useful
  Chinese coverage, but the files are reconstructed JSONL rather than original
  MIME and the upstream competition-data rights have not been independently
  verified. It remains audit-only until that is cleared.
- [LLM-Generated Phishing Email Dataset](https://huggingface.co/datasets/Dizzzy0x00/LLMGen-Phishing-Email-Dataset)
  is Apache-2.0 and contains 6,776 Chinese/English synthetic messages. It is
  suitable for an adversarial coverage check, not training or production error
  claims.
- Three MIT-licensed transactional-template repositories contribute 20 one-to-one
  English Ham supplements: Postmark (11), MailPace (6), and Mailgun (3). They
  cover password resets, confirmations, security alerts, receipts, billing,
  invitations, and notifications. They are explicitly not treated as real traffic
  or expanded into variants.
- Keycloak's Apache-2.0 official `zh_Hans` email localization contributes 15
  one-to-one Chinese transactional/security messages (13 detected as Chinese and
  2 as mixed after URL/product-name expansion). Across all four template sources,
  the combined theoretical Ham cap is 8% and the actual contribution is 35 messages.

The practical consequence is that recent, authorized Octo/test mailbox exports
must be the primary data. Public legacy samples are capped at 10% per class.

## Leakage and split controls

The local corpus workspace at `../octo-mail-junk-corpus` contains the reproducible
pipeline. It:

1. removes `X-Spam-*`, `X-Rspamd-*`, and similar label-leaking headers;
2. keeps the remaining RFC 5322/MIME bytes for the actual trainer;
3. performs SHA-256 exact deduplication and normalized-content SimHash clustering;
4. caps each template cluster at 20 messages;
5. keeps template, thread, and sender-domain groups on one side of train/eval;
6. enforces the intended language mix and per-source caps;
7. fails closed instead of producing a “production” corpus when quotas are short.

The current dry run selects only 468/5,000 train Ham, 832/5,000 train Spam,
202/1,500 evaluation Ham, and 303/1,500 evaluation Spam after caps and split
isolation. Chinese coverage is especially insufficient. The shared model must
therefore remain untrained/disabled until authorized recent traffic fills the
gap.

## Evaluation gate

- Shared classification starts only after both classes have at least 200 learns,
  matching Rspamd's documented conservative `min_learns` default. This is an
  activation floor, not a quality claim.
- The shared threshold is selected using the frozen evaluation set. The
  conservative runtime default is 0.9999 and remains configurable.
- `octo-mail junk evaluate-global` scores the holdout through the exact bounded
  shared-model path used in production. It is read-only
  and reports per-message probabilities, overall and per-language metrics, plus
  the threshold immediately above the highest Ham score.
- Verification and security-notification Ham require zero false positives in the
  evaluation set.
- Overall Ham-to-Junk false-positive rate target is below 0.1%.
- Initial Spam recall target is at least 80%.
- If these conditions are not met, keep the shared model disabled or adjust the
  corpus/threshold; do not compensate by allowing the shared model to reject mail.

## Local quality experiment

The private offline experiment keeps content/subject groups disjoint between
training and evaluation. The current package adds a small, content-only
short-Chinese regression supplement to the original corpus, for 625 Ham and
1,259 Spam training samples in total. At the 0.9999 shared threshold it produced
zero false positives across the original 420 recent private Ham messages and a
separate 20-message short-Chinese collaboration holdout. It detected 387 of 420
messages in the original Spam holdout and 18 of 20 messages in the separate
short-Chinese Spam holdout. This is useful threshold evidence for the
internal-only package: Inbox placement is a provisional Ham label and the
Chinese phishing supplement is not approved for public model distribution.

## Release boundary

The evaluated corpus and generated model are internal release inputs, not public
source artifacts. A release package contains only SHA-256 feature identifiers
and aggregate Ham/Spam counters; it contains no raw message, address, subject, or
body. The public repository ignores the generated package while an internal
image build may embed it for automatic first-start import.

The generated v2 package contains 625 Ham learns, 1,259 Spam learns, and 76,438
hashed feature counters (2.5 MiB compressed). A fresh-database import followed
by the frozen evaluation must reproduce the recorded results before the package
is used by a local image.
