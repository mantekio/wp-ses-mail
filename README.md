# WP SES Mail

[![Packagist Version](https://img.shields.io/packagist/v/mantekio/wp-ses-mail)](https://packagist.org/packages/mantekio/wp-ses-mail) [![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)

A WordPress **must-use plugin** that sends mail through **Amazon SES**, authenticated by an **IAM role**, so there are no credentials stored anywhere and no send failures that pass silently.

> 📖 **Full write-up:** [Your WordPress mail credentials are sitting in your database](https://www.mantek.io/insights/wordpress-email-ses)

## The problem

By default `wp_mail()` hands your message to PHP's `mail()` and out through `sendmail`: no sending reputation, no SPF alignment, no DKIM signature, so modern providers bin it as spam, often without even a bounce. And `wp_mail()`'s entire failure vocabulary is a single `false`. On the default path it does not even return that: `sendmail` accepts the message, `wp_mail()` returns `true`, and the mail dies downstream where WordPress never hears about it. A password reset that never arrives, with nothing in the logs.

The usual fix is an SMTP plugin. It fixes authentication, but it stores the SMTP username and password in `wp_options`. Every database dump, backup, and staging clone then carries a credential that can send mail as your domain, DKIM-signed, with no fingerprint that it was not you. That is a liability with a settings screen.

## What it does

- **Sends via the SES API, not SMTP.** A signed HTTPS request, so there is no long-lived password in the flow at all.
- **Authenticates with an IAM role.** Credentials come from the AWS default chain (env vars, then the ECS task role, then the EC2 instance role), read at send time and never written to the database, `wp-config.php`, or disk. There is no secret at rest to leak.
- **Replaces only the transport.** It hands core a **subclass** of PHPMailer on `pre_wp_mail` and overrides one method, `postSend()`. Core still builds the whole message and honours every `wp_mail_*` filter, so no core contract is reimplemented and nothing can drift.
- **Fails loudly, never falls back.** An SES rejection returns `false` with the real SES error via `wp_mail_failed`. A misconfiguration **refuses to send** (on every admin screen and in the log) rather than falling through to `sendmail` and spam.
- **Remembers bounces and complaints.** A signed, topic-pinned SNS endpoint records hard bounces and complaints to a suppression table that is checked before every send, so a dead or complaining address is never mailed again and your SES reputation stays intact.
- **Ships a real health check.** `wp ses verify` signs live requests with the same code the send path uses, and **exits non-zero** when anything is wrong, so `wp ses verify || alert` works in cron.

## Requirements

- **WordPress 5.7+**, for the `pre_wp_mail` hook. On older versions there is no seam: mail falls through to `sendmail` and the plugin can warn but cannot stop it.
- **PHP 7.4+**, with the `openssl` and `curl` extensions.
- WordPress running on **AWS compute with an IAM role** allowing `ses:SendEmail` (plus `ses:GetAccount` and `ses:GetEmailIdentity` for `verify`). Off AWS, the standard `AWS_*` environment variables work.
- A **verified SES identity** to send from (a domain, with Easy DKIM, is what makes mail align).

## Installation

A must-use plugin loads before regular plugins and cannot be deactivated by accident.

**Manual**
```bash
mkdir -p wp-content/mu-plugins
cp wp-ses-mail.php wp-content/mu-plugins/
```

**Composer**
```bash
composer require mantekio/wp-ses-mail
```

Composer installs it as a [`wordpress-muplugin`](https://github.com/composer/installers), which has two consequences worth knowing:

- **Allow the installer plugin.** On a fresh project Composer blocks `composer/installers` until you permit it. Add this to your root `composer.json` (most WordPress-Composer stacks already have it):
  ```json
  { "config": { "allow-plugins": { "composer/installers": true } } }
  ```
- **Make sure it actually loads.** It installs into `wp-content/mu-plugins/wp-ses-mail/` (a subfolder), and vanilla WordPress only auto-loads `*.php` placed *directly* in `mu-plugins/`. Rely on a mu-plugins autoloader (Bedrock and similar stacks ship one), or use the **Manual** method above to drop the single file straight in.

## Configuration

Define in `wp-config.php` (never the database):

| Constant | Required | Meaning |
|---|---|---|
| `WP_SES_REGION` | yes\* | SES region, e.g. `eu-west-1`. \*Falls back to the `AWS_REGION` environment variable. |
| `WP_SES_FROM` | yes | Default From address, a verified SES identity, e.g. `noreply@example.com`. |
| `WP_SES_SNS_TOPIC_ARN` | for bounces | The SNS topic ARN SES publishes bounce/complaint events to. The endpoint fails closed until this is set (see [Bounces](#bounces-and-complaints)). |
| `WP_SES_CONFIGURATION_SET` | no | SES configuration set, for event tracking. |
| `WP_SES_ALERT_EMAIL` | no | Best-effort address to alert on a serious send failure. |
| `WP_SES_ENDPOINT` | test only | Override the SES endpoint at a local simulator (e.g. LocalStack). Leave unset in production. |

```php
define( 'WP_SES_REGION', 'eu-west-1' );
define( 'WP_SES_FROM',   'noreply@example.com' );
define( 'WP_SES_SNS_TOPIC_ARN', 'arn:aws:sns:eu-west-1:123456789012:ses-events' );
```

No credentials go here. The IAM role provides them.

## Bounces and complaints

SES holds you to bounce and complaint thresholds; cross them and it throttles your sending, then suspends the account. WordPress has no memory of a bounce and will email a dead address forever, so the plugin keeps that memory for it.

1. In SES, set the identity's bounce and complaint notifications to publish to an **SNS topic**, and set `WP_SES_SNS_TOPIC_ARN` to its ARN.
2. Subscribe the topic to the endpoint `https://your-site/wp-json/wpses/v1/sns`. The plugin auto-confirms the subscription.
3. From then on, hard bounces and complaints are written to the suppression table and blocked before the next send.

**Security.** That endpoint is a public URL. AWS shares one regional signing certificate across all customers, so a valid signature alone only proves a message came from *some* topic. The endpoint therefore **pins your topic ARN** and **verifies the SNS signature** on every message, and **fails closed** until the ARN is set, so no one can forge a notification to suppress your users' mail.

Lift a wrongly-suppressed address:
```bash
wp ses unsuppress --email=someone@example.com
```

## Verifying

```bash
wp ses verify
```

It reports region, credential source, identity verification, DKIM, sandbox state, quota, and whether the bounce topic is wired up, and it **exits non-zero** on any problem, so it composes into cron:

```bash
# nightly: page if the SES config ever drifts
0 3 * * *  cd /var/www/site && wp ses verify || wp ses verify | mail -s "SES broken on $(hostname)" ops@example.com
```

## Hooks

Actions you can hook for logging, metrics, or alerting:

| Action | Fires when |
|---|---|
| `wpses_sent` | A send succeeded. Passes the SES `MessageId` and the `Destination`. |
| `wpses_send_failed` | A send failed. Passes a `WP_Error`. |
| `wpses_suppression_unreadable` | The suppression table could not be read, so the plugin failed open loudly (sent anyway) rather than block mail on a database blip. |

## Known limits

- It is a **transactional transport, not a bulk queue.** A newsletter blast to tens of thousands of subscribers wants a queue and probably a dedicated bulk sender; leaning on this for that just meets SES throttling as a failed send.
- **No retry or backoff yet.** A refused send fails loudly and stops; durable retries belong in a queue in front of the plugin.
- **Message-size ceiling.** SES caps the size of a single message; a mail with very large inline attachments will fail rather than be silently truncated.
- **Alignment is DNS, not the plugin.** DKIM, SPF, and DMARC alignment are records you add. The plugin signs the request and can tell you they are missing, but cannot add them for you.
- **WordPress 5.7+ only** (see [Requirements](#requirements)).

## How it works

The full reasoning (why a subclass and not the `pre_wp_mail` fork, why loud failure and no fallback, the SNS signature trap, and the newsroom bounce loop) is in the write-up:

**→ [Your WordPress mail credentials are sitting in your database](https://www.mantek.io/insights/wordpress-email-ses)**

## License

[GPL-2.0-or-later](LICENSE): same as WordPress.

---

Built and maintained by **[ManTek Technologies](https://www.mantek.io)**: WordPress + AWS at scale, for newsrooms and beyond.
