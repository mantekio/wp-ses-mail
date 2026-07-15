# Changelog

All notable changes to **WP SES Mail** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-07-16

First public release, pre-1.0 and feature-complete, hardened through repeated
adversarial review, with the SES signing checked against AWS's own SigV4 test
vectors. **Not yet verified end-to-end against a live Amazon SES account** (a real
`MessageId`, DKIM/SPF/DMARC alignment, a live loud rejection, the bounce loop):
that verification is what promotes it to a stable `1.0.0`.

### Added
- Initial WordPress must-use plugin that sends `wp_mail()` through the Amazon SES
  API, authenticated by an IAM role from the AWS default credential chain, so no
  SMTP secret is stored in the database, `wp-config.php`, or on disk.
- **Transport by subclass.** Hands core a `PHPMailer` subclass on `pre_wp_mail`
  and overrides only `postSend()`, so core still builds the message and honours
  every `wp_mail_*` filter, and none of its contract is reimplemented.
- **Loud failure, no fallback.** An SES rejection returns `false` with the real
  error via `wp_mail_failed`; a misconfiguration refuses to send rather than fall
  through to `sendmail`.
- **Bounce and complaint suppression.** A signed, topic-pinned SNS endpoint
  (`/wp-json/wpses/v1/sns`) records hard bounces and complaints to a suppression
  table that is checked before every send.
- **WP-CLI:** `wp ses verify` (signs live requests, exits non-zero on any
  problem) and `wp ses unsuppress`.
- Actions: `wpses_sent`, `wpses_send_failed`, `wpses_suppression_unreadable`.
- Single file, no AWS SDK, hand-rolled SigV4.

[0.9.0]: https://github.com/mantekio/wp-ses-mail/releases/tag/v0.9.0
