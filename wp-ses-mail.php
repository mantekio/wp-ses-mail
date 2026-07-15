<?php
/**
 * Plugin Name: WP SES Mail
 * Description: Sends WordPress mail through Amazon SES with no credentials stored anywhere. Must-use plugin.
 * Version:     0.9.0
 * Author:      ManTek Technologies
 * Author URI:  https://www.mantek.io
 * License:     GPL-2.0-or-later
 *
 * WHY THIS EXISTS
 * ---------------
 * WordPress sends mail through PHP's mail() by default: no SPF alignment, no DKIM,
 * the web server's IP reputation, and wp_mail() returns a bare bool. A password
 * reset that never arrives is the result, and nothing in the logs says so.
 *
 * The usual fix is an SMTP plugin, which stores the SMTP username and password in
 * wp_options. A database dump, an old backup, a staging clone, and someone can send
 * mail AS YOU, DKIM-signed by your own domain. That is not a fix, it is a liability
 * with a settings screen.
 *
 * This plugin sends via the SES API, authenticated by an IAM role. There are no
 * credentials in the database, in wp-config, or on disk. Nothing to leak.
 *
 * HOW IT HOOKS IN (and why not the obvious way)
 * ---------------------------------------------
 * wp_mail() offers a real short-circuit filter, `pre_wp_mail` (WP 5.7+). Returning
 * non-null from it replaces wp_mail() outright. That is tempting and it is a trap:
 * you then own core's entire contract, header parsing, Cc/Bcc, Reply-To, charset,
 * content type, attachments, every wp_mail_* filter. A hand-copy of that contract
 * drifts from core silently, which is exactly how our last fork of a core function
 * rotted for three releases.
 *
 * So we do not reimplement anything. Core builds its PHPMailer object only when the
 * global is not already one, so we hand it a SUBCLASS whose postSend() ships the
 * finished message to SES. Core does all the message construction and honours every
 * filter. We replace the transport and nothing else. There is no contract to drift.
 *
 * Recipients are handed to SES EXPLICITLY as a Destination, never inferred from the
 * MIME headers: header inference only holds while PHPMailer is in 'mail' mode, and any
 * coexisting SMTP plugin flips it to 'smtp', at which point Bcc silently disappears.
 *
 * THERE IS NO FALLBACK, ON PURPOSE
 * --------------------------------
 * When SES refuses a message we throw, which lands in core's own wp_mail_failed
 * action and makes wp_mail() return false, with the real SES error in the log. We
 * never fall back to PHP mail(): that fallback looks safe and is the opposite, the
 * mail appears to send and lands in spam. A loud failure gets fixed; a silent one is
 * never noticed. A misconfigured plugin refuses to send rather than use sendmail.
 *
 * CONFIGURATION (wp-config.php, never the database)
 * ------------------------------------------------
 *   define( 'WP_SES_REGION', 'eu-west-1' );              // required
 *   define( 'WP_SES_FROM', 'noreply@example.com' );      // required; a verified SES identity
 *   define( 'WP_SES_CONFIGURATION_SET', 'default' );     // optional; for SES event tracking
 *   define( 'WP_SES_ALERT_EMAIL', 'ops@example.com' );   // optional; best-effort alert (see wpses_fail)
 *   define( 'WP_SES_ENDPOINT', 'http://localhost:4566' );// TEST ONLY: point at a local SES
 *        // simulator (e.g. LocalStack). Leave unset in production; it defaults to the real
 *        // AWS endpoint. Same trust level as the other constants (it takes wp-config access).
 *   define( 'WP_SES_SNS_TOPIC_ARN', 'arn:aws:sns:eu-west-1:123456789012:ses-events' );
 *        // REQUIRED to use the bounce/complaint endpoint. AWS shares one regional
 *        // signing certificate across all customers, so a valid signature alone only
 *        // proves the message came from SOME topic. Without pinning the ARN, anyone can
 *        // suppress your users' mail. The endpoint fails closed until this is set.
 *
 * Credentials come from the AWS default chain: env vars first (so a non-AWS host never
 * pays the metadata timeout), then the ECS task role, then the EC2 instance role. There
 * is deliberately no way to put a secret key in the database.
 *
 * KNOWN LIMIT: on WordPress older than 5.7 there is no pre_wp_mail hook, so the
 * transport cannot be installed AND we cannot intercept to refuse. Mail falls through
 * to PHP mail(). The plugin says so loudly, but it cannot stop it. Run 5.7+.
 */

defined( 'ABSPATH' ) || exit;

defined( 'WP_SES_REGION' ) || define( 'WP_SES_REGION', (string) getenv( 'AWS_REGION' ) );

/* REFUSAL
 * A plugin that silently does nothing is worse than one that is absent. When we cannot
 * do our job we log it, put it on every admin screen, and REFUSE THE SEND, rather than
 * let WordPress fall through to sendmail and spam. */
function wpses_refuse( $why ) {
    error_log( "[wp-ses-mail] REFUSING TO SEND: {$why}" );

    add_action( 'admin_notices', function () use ( $why ) {
        echo '<div class="notice notice-error"><p><strong>WP SES Mail is not configured.</strong> '
            . esc_html( $why ) . ' Mail is <strong>being refused</strong>, not silently sent to spam.</p></div>';
    } );

    add_filter( 'pre_wp_mail', function ( $short, $atts ) use ( $why ) {
        do_action(
            'wp_mail_failed',
            new WP_Error( 'wpses_not_configured', "WP SES Mail is not configured: {$why}", $atts )
        );
        return false;   // short-circuit: not sent, and wp_mail() returns false.
    }, 1, 2 );
}

if ( version_compare( (string) $GLOBALS['wp_version'], '5.7', '<' ) ) {
    wpses_refuse( 'WordPress 5.7 or newer is required (the pre_wp_mail hook).' );
    return;
}
if ( ! WP_SES_REGION || ! defined( 'WP_SES_FROM' ) || ! WP_SES_FROM ) {
    wpses_refuse( 'WP_SES_REGION and WP_SES_FROM must be defined in wp-config.php.' );
    return;
}

/* THE TRANSPORT
 * Core builds the message; we only carry it. postSend() runs after preSend() has
 * assembled the full MIME, so getSentMIMEMessage() is exactly what core intended. */
add_filter( 'pre_wp_mail', 'wpses_install_mailer', 1, 2 );

function wpses_install_mailer( $short_circuit, $atts ) {
    if ( ! class_exists( 'WPSES_Mailer', false ) ) {
        require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
        require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';

        class WPSES_Mailer extends \PHPMailer\PHPMailer\PHPMailer {
            public function postSend() {
                // Recipients are passed EXPLICITLY, split by kind, so delivery never
                // depends on which transport mode PHPMailer happens to be in.
                $sent = wpses_send_raw(
                    $this->getSentMIMEMessage(),
                    $this->getToAddresses(),
                    $this->getCcAddresses(),
                    $this->getBccAddresses()
                );

                if ( is_wp_error( $sent ) ) {
                    // Throwing lands in core's own catch, which fires wp_mail_failed and
                    // returns false. Anything already listening keeps working.
                    throw new \PHPMailer\PHPMailer\Exception( $sent->get_error_message() );
                }
                return true;
            }
        }
    }

    if ( ! ( $GLOBALS['phpmailer'] instanceof WPSES_Mailer ) ) {
        $GLOBALS['phpmailer'] = new WPSES_Mailer( true );
    }
    return $short_circuit;
}

/* SEND
 * SES v2, raw content with an EXPLICIT Destination. Suppressed recipients are dropped
 * here, loudly, rather than mailed; if that leaves no one, the send fails rather than
 * pretending to succeed. */
function wpses_send_raw( $raw, array $to = array(), array $cc = array(), array $bcc = array() ) {
    // Two failure modes, deliberately treated differently:
    //   definitively absent / uncreatable table -> fail CLOSED. That is an operator config
    //     error, and a loud mail outage beats silently mailing suppressed addresses and
    //     torching the SES reputation.
    //   transient DB error (a blip, a deadlock, "too many connections") -> fail OPEN, but
    //     loudly. The recipient's status is unknown, not bad; the odds this one address is
    //     suppressed are low, while blocking its password reset during a DB incident is the
    //     worse harm, and it strikes exactly when the DB is already struggling.
    $schema = wpses_ensure_schema();
    if ( false === $schema ) {
        wpses_fail( 'suppression list unavailable (table missing, not creatable); refusing to send', null );
        return new WP_Error( 'wpses_suppression_unavailable', 'Suppression list unavailable; refusing to send.' );
    }
    $suppression_unknown = ( null === $schema );
    if ( $suppression_unknown ) {
        error_log( '[wp-ses-mail] suppression table temporarily unreadable; sending WITHOUT the suppression check (transient DB error, not a bad address).' );
        do_action( 'wpses_suppression_unreadable', null, 'schema check' );
    }

    $dropped = array();
    $dest    = array();
    foreach ( array( 'ToAddresses' => $to, 'CcAddresses' => $cc, 'BccAddresses' => $bcc ) as $key => $list ) {
        $keep = array();
        foreach ( $list as $addr ) {
            $email = is_array( $addr ) ? $addr[0] : $addr;
            if ( ! $suppression_unknown ) {
                $sup = wpses_is_suppressed( $email );
                if ( is_wp_error( $sup ) ) {
                    // Per-recipient transient read error: same policy, fail open loudly.
                    error_log( '[wp-ses-mail] suppression unreadable for ' . $email
                        . ' (' . $sup->get_error_message() . '); sending anyway (transient DB error).' );
                    do_action( 'wpses_suppression_unreadable', $email, $sup );
                    $keep[] = $email;
                    continue;
                }
                if ( $sup ) {
                    $dropped[] = $email;
                    continue;   // a dropped Cc still appears in the visible Cc: header (public; not a leak)
                }
            }
            $keep[] = $email;
        }
        if ( $keep ) {
            $dest[ $key ] = $keep;
        }
    }
    if ( $dropped ) {
        error_log( '[wp-ses-mail] dropped suppressed recipient(s): ' . implode( ', ', $dropped ) );
    }
    if ( empty( $dest ) ) {
        wpses_fail( 'every recipient is suppressed; nothing to send', null );
        return new WP_Error( 'wpses_all_suppressed', 'Every recipient is on the suppression list.' );
    }

    $creds = wpses_credentials();
    if ( is_wp_error( $creds ) ) {
        wpses_fail( 'no credentials: ' . $creds->get_error_message(), null );
        return $creds;
    }

    // Bcc travels in the envelope above, so strip it from the visible headers rather
    // than trusting SES to remove it. This cannot leak Bcc to the other recipients.
    $raw = wpses_strip_bcc_header( $raw );

    $body = array(
        'Content'     => array( 'Raw' => array( 'Data' => base64_encode( $raw ) ) ),
        'Destination' => $dest,
    );
    if ( defined( 'WP_SES_CONFIGURATION_SET' ) && WP_SES_CONFIGURATION_SET ) {
        $body['ConfigurationSetName'] = WP_SES_CONFIGURATION_SET;
    }

    $base     = wpses_endpoint();
    $path     = '/v2/email/outbound-emails';
    $payload  = wp_json_encode( $body );
    $response = wp_remote_post( $base . $path, array(
        'headers' => wpses_sigv4( 'POST', wpses_sig_host( $base ), $path, $payload, $creds ),
        'body'    => $payload,
        'timeout' => 15,
    ) );

    if ( is_wp_error( $response ) ) {
        wpses_fail( 'transport error: ' . $response->get_error_message(), null );
        return $response;
    }

    $code = (int) wp_remote_retrieve_response_code( $response );
    $json = json_decode( wp_remote_retrieve_body( $response ), true );

    if ( 200 !== $code ) {
        // SES tells you exactly why. Never swallow it: "false" is not a diagnosis.
        $type = wp_remote_retrieve_header( $response, 'x-amzn-errortype' ) ?: 'Unknown';
        $msg  = isset( $json['message'] ) ? $json['message'] : 'no message';
        wpses_fail( "SES rejected the message [{$code} {$type}]: {$msg}", $raw );
        return new WP_Error( 'wpses_rejected', "SES {$type}: {$msg}" );
    }

    // A 200 with no MessageId is not success. Reporting it as sent is the
    // proxy-not-outcome trap in miniature.
    if ( empty( $json['MessageId'] ) ) {
        wpses_fail( '200 from SES but no MessageId in the response', $raw );
        return new WP_Error( 'wpses_no_message_id', 'SES returned 200 without a MessageId.' );
    }
    // Symmetric with wpses_send_failed: let ops observe successful sends by their real
    // outcome (the MessageId) without every send hitting the error log. The live-test
    // runbook hooks this to capture the id rather than lean on the laggy SES stats counter.
    do_action( 'wpses_sent', $json['MessageId'], $dest );
    return $json['MessageId'];
}

/**
 * Remove the Bcc header (and any folded continuation lines) from the header block only,
 * for every header position. Body bytes are preserved verbatim. Bcc is delivered via the
 * SES Destination envelope, so it must not remain visible in the message.
 */
function wpses_strip_bcc_header( $raw ) {
    $boundary = strpos( $raw, "\r\n\r\n" );
    if ( false === $boundary ) {
        $boundary = strpos( $raw, "\n\n" );
    }
    if ( false === $boundary ) {
        return $raw;   // no header/body boundary found; do not touch it
    }
    $headers = substr( $raw, 0, $boundary );
    $rest    = substr( $raw, $boundary );   // separator + body, untouched
    $eol     = ( false !== strpos( $headers, "\r\n" ) ) ? "\r\n" : "\n";

    $out  = array();
    $skip = false;
    foreach ( explode( $eol, $headers ) as $line ) {
        $is_continuation = ( '' !== $line && ( ' ' === $line[0] || "\t" === $line[0] ) );
        if ( $is_continuation ) {
            if ( ! $skip ) {
                $out[] = $line;   // continuation of a kept header
            }
            continue;             // continuation of a dropped header: skip too
        }
        $skip = ( 0 === stripos( $line, 'Bcc:' ) );
        if ( ! $skip ) {
            $out[] = $line;
        }
    }
    return implode( $eol, $out ) . $rest;
}

/* LOUD FAILURE
 * wp_mail() returns a bool and swallows the reason. That is how a password reset
 * disappears. Log the real error and fire an action, always.
 *
 * The optional email alert is BEST EFFORT ONLY: it rides the same SES channel that just
 * failed, so on the most important failures (bad credentials, SES down) it cannot
 * arrive. It is not the monitor. `wp ses verify` in cron is the monitor. The error_log
 * line and the wpses_send_failed action below are what you actually build alerting on.
 * The static guard stops the alert send from recursing into this function. */
function wpses_fail( $reason, $raw ) {
    static $alerting = false;

    error_log( "[wp-ses-mail] SEND FAILED: {$reason}" );
    do_action( 'wpses_send_failed', $reason, $raw );

    if ( $alerting ) {
        return;   // already inside the alert send; never re-enter
    }
    if ( ! defined( 'WP_SES_ALERT_EMAIL' ) || ! WP_SES_ALERT_EMAIL || get_transient( 'wpses_alerted' ) ) {
        return;
    }
    set_transient( 'wpses_alerted', 1, HOUR_IN_SECONDS );

    $alerting = true;
    wp_mail( WP_SES_ALERT_EMAIL, 'WP SES Mail: send failed', $reason );  // may itself fail; that is fine
    $alerting = false;
}

/* CREDENTIALS
 * The whole point of the plugin. Order matches the AWS default chain: env, then ECS
 * task role, then EC2 instance role. Env first means a non-AWS host never pays the
 * 169.254.x metadata timeout. There is no database branch, and there never will be.
 * Cached in memory for the request only: a transient would put temporary credentials in
 * wp_options, which is the exact thing we are here to avoid. */
function wpses_credentials() {
    static $cache = null;
    if ( null !== $cache && $cache['expires'] > time() + 60 ) {
        return $cache;
    }

    // 1. Environment (also the only path on non-AWS hosts).
    $key = getenv( 'AWS_ACCESS_KEY_ID' );
    $sec = getenv( 'AWS_SECRET_ACCESS_KEY' );
    if ( $key && $sec ) {
        return $cache = array(
            'key'     => $key,
            'secret'  => $sec,
            'token'   => (string) getenv( 'AWS_SESSION_TOKEN' ),
            'expires' => time() + 3600,
            'source'  => 'env',
        );
    }

    // 2. ECS / Fargate task role.
    $rel = getenv( 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI' );
    if ( $rel ) {
        $creds = wpses_fetch_creds( 'http://169.254.170.2' . $rel, array() );
        if ( ! is_wp_error( $creds ) ) {
            $creds['source'] = 'ecs-task-role';
            return $cache = $creds;
        }
    }

    // 3. EC2 instance role, IMDSv2 (token-first; IMDSv1 is disabled on hardened hosts).
    $token = wp_remote_request( 'http://169.254.169.254/latest/api/token', array(
        'method'  => 'PUT',
        'timeout' => 2,
        'headers' => array( 'X-aws-ec2-metadata-token-ttl-seconds' => '21600' ),
    ) );
    if ( ! is_wp_error( $token ) && 200 === (int) wp_remote_retrieve_response_code( $token ) ) {
        $hdr  = array( 'X-aws-ec2-metadata-token' => wp_remote_retrieve_body( $token ) );
        $role = wp_remote_get( 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', array(
            'timeout' => 2,
            'headers' => $hdr,
        ) );
        $name = is_wp_error( $role ) ? '' : trim( wp_remote_retrieve_body( $role ) );
        if ( $name ) {
            $creds = wpses_fetch_creds(
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/' . rawurlencode( $name ),
                $hdr
            );
            if ( ! is_wp_error( $creds ) ) {
                $creds['source'] = 'ec2-instance-role';
                return $cache = $creds;
            }
        }
    }

    return new WP_Error(
        'wpses_no_credentials',
        'No AWS credentials: no AWS_* environment variables, no ECS task role, no EC2 instance role.'
    );
}

function wpses_fetch_creds( $url, array $headers ) {
    $res = wp_remote_get( $url, array( 'timeout' => 2, 'headers' => $headers ) );
    if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
        return new WP_Error( 'wpses_creds_unavailable', 'Credential endpoint did not answer.' );
    }
    $j = json_decode( wp_remote_retrieve_body( $res ), true );
    if ( empty( $j['AccessKeyId'] ) || empty( $j['SecretAccessKey'] ) ) {
        return new WP_Error( 'wpses_creds_malformed', 'Credential endpoint returned no key.' );
    }
    return array(
        'key'     => $j['AccessKeyId'],
        'secret'  => $j['SecretAccessKey'],
        'token'   => isset( $j['Token'] ) ? $j['Token'] : '',
        'expires' => isset( $j['Expiration'] ) ? strtotime( $j['Expiration'] ) : time() + 900,
    );
}

/** SES base URL. Overridable for local testing (LocalStack and similar); defaults to the
 *  real AWS endpoint. In production leave WP_SES_ENDPOINT unset. */
function wpses_endpoint() {
    if ( defined( 'WP_SES_ENDPOINT' ) && WP_SES_ENDPOINT ) {
        return rtrim( WP_SES_ENDPOINT, '/' );
    }
    return 'https://email.' . WP_SES_REGION . '.amazonaws.com';
}

/** The Host header value to sign: the host, plus a non-default port when one is present
 *  (so a LocalStack endpoint on :4566 signs correctly, and real AWS on 443 does not). */
function wpses_sig_host( $base ) {
    $host = (string) wp_parse_url( $base, PHP_URL_HOST );
    $port = wp_parse_url( $base, PHP_URL_PORT );
    return $port ? "{$host}:{$port}" : $host;
}

/* SIGV4
 * Roughly forty lines, which is why this plugin needs no AWS SDK and stays a single
 * file you can drop into mu-plugins and read end to end. */
function wpses_sigv4( $method, $host, $path, $payload, array $creds ) {
    $service = 'ses';
    $region  = WP_SES_REGION;
    $now     = gmdate( 'Ymd\THis\Z' );
    $date    = gmdate( 'Ymd' );
    $hash    = hash( 'sha256', $payload );

    $signed_headers = 'content-type;host;x-amz-content-sha256;x-amz-date';
    $canonical      = "content-type:application/json\n"
                    . "host:{$host}\n"
                    . "x-amz-content-sha256:{$hash}\n"
                    . "x-amz-date:{$now}\n";

    if ( $creds['token'] ) {
        $signed_headers = 'content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token';
        $canonical     .= "x-amz-security-token:{$creds['token']}\n";
    }

    $canonical_request = "{$method}\n{$path}\n\n{$canonical}\n{$signed_headers}\n{$hash}";
    $scope             = "{$date}/{$region}/{$service}/aws4_request";
    $string_to_sign    = "AWS4-HMAC-SHA256\n{$now}\n{$scope}\n" . hash( 'sha256', $canonical_request );

    $k = hash_hmac( 'sha256', $date, 'AWS4' . $creds['secret'], true );
    $k = hash_hmac( 'sha256', $region, $k, true );
    $k = hash_hmac( 'sha256', $service, $k, true );
    $k = hash_hmac( 'sha256', 'aws4_request', $k, true );
    $signature = hash_hmac( 'sha256', $string_to_sign, $k );

    $headers = array(
        'Content-Type'         => 'application/json',
        'X-Amz-Content-Sha256' => $hash,
        'X-Amz-Date'           => $now,
        'Authorization'        => "AWS4-HMAC-SHA256 Credential={$creds['key']}/{$scope}, "
                                . "SignedHeaders={$signed_headers}, Signature={$signature}",
    );
    if ( $creds['token'] ) {
        $headers['X-Amz-Security-Token'] = $creds['token'];
    }
    return $headers;
}

/* SUPPRESSION
 * SES enforces bounce and complaint thresholds and will throttle, then suspend you.
 * WordPress will happily email a dead address forever, so we keep a list and check it
 * before sending.
 *
 * It is a dedicated table, not a serialized option. A single wp_options blob is
 * read-modify-written on every bounce with no lock, so two bounces arriving together
 * (routine during a newsroom send) lose each other's writes, and a genuinely bad address
 * is never suppressed. INSERT IGNORE against a UNIQUE key is atomic; the lookup is
 * indexed; growth is bounded per address. The email index is a 191-char prefix, the
 * classic utf8mb4 index-length guard. */
function wpses_suppress_table() {
    global $wpdb;
    return $wpdb->prefix . 'ses_suppressions';
}

/** Does the table exist RIGHT NOW? The wpses_db_version option is not proof: the table
 *  can be dropped in maintenance or a partial restore while the option survives.
 *  Tri-state: true = exists, false = definitively absent (the query ran and found none),
 *  null = COULD NOT DETERMINE (a transient DB error). That last distinction is what lets
 *  the send path fail closed on a permanent fault but fail open, loudly, on a passing
 *  blip, rather than blocking every password reset the moment the DB is under load. */
function wpses_table_exists() {
    global $wpdb;
    $wpdb->last_error = '';
    $found = $wpdb->get_var(
        $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( wpses_suppress_table() ) )
    );
    if ( '' !== $wpdb->last_error ) {
        return null;
    }
    return null !== $found;
}

/**
 * Ensure the table exists, then confirm the OUTCOME before recording success.
 *
 * The previous version set wpses_db_version unconditionally after dbDelta(). dbDelta()
 * does not throw on failure, so a table that never got created (no CREATE privilege, a
 * collation edge, a later DROP) was marked "done" and never retried, wpses_is_suppressed()
 * then read the resulting DB error as "not suppressed", and wp ses verify reported green.
 * Bounces were never enforced while the plugin claimed to be fine: the exact silent-
 * suppression failure this plugin calls its cardinal sin, committed by the fix for it.
 *
 * Tri-state, mirroring wpses_table_exists(): true = ready, false = definitively
 * absent/uncreatable (fail closed), null = transient DB error, could not determine (the
 * caller fails open, loudly). Lazy (not hooked to init), so a healthy page load pays
 * nothing. $force bypasses the negative cache below (used by `wp ses verify`).
 */
function wpses_ensure_schema( $force = false ) {
    $exists = wpses_table_exists();
    if ( true === $exists ) {
        if ( '1' !== get_option( 'wpses_db_version' ) ) {
            update_option( 'wpses_db_version', '1', true );
        }
        delete_transient( 'wpses_schema_failed' );
        return true;
    }
    if ( null === $exists ) {
        return null;   // transient: could not determine. Caller fails open, loudly.
    }

    // Definitively absent. Throttle the create: without a negative cache, an uncreatable
    // table re-runs the whole dbDelta (many metadata queries) and floods the log on every
    // single send. verify passes $force to retry immediately.
    if ( ! $force && get_transient( 'wpses_schema_failed' ) ) {
        return false;
    }

    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $table = wpses_suppress_table();
    dbDelta(
        "CREATE TABLE {$table} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            email varchar(255) NOT NULL,
            reason varchar(40) NOT NULL DEFAULT '',
            created_at int unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY email (email(191))
        ) " . $wpdb->get_charset_collate() . ';'
    );

    $after = wpses_table_exists();
    if ( true === $after ) {
        update_option( 'wpses_db_version', '1', true );
        delete_transient( 'wpses_schema_failed' );
        return true;
    }
    if ( null === $after ) {
        return null;   // transient during/after create; do not conclude "uncreatable"
    }

    // Genuinely uncreatable. Do not mark it done (keep retrying, throttled), and refuse.
    delete_option( 'wpses_db_version' );
    set_transient( 'wpses_schema_failed', 1, MINUTE_IN_SECONDS );
    error_log( '[wp-ses-mail] suppression table could not be created; suppression is DISABLED until fixed. Check the DB user has CREATE.' );
    return false;
}

/**
 * true = suppressed, false = not on the list, WP_Error = COULD NOT CHECK.
 *
 * A DB error must never collapse to "false" and read as "safe to send", that is the
 * fail-open this subsystem exists to refuse. The send path treats the WP_Error as a hard
 * failure and declines to send rather than mail a possibly-suppressed address blind.
 */
function wpses_is_suppressed( $email ) {
    global $wpdb;
    $email = strtolower( trim( (string) $email ) );
    if ( '' === $email ) {
        return false;
    }
    $table            = wpses_suppress_table();
    $wpdb->last_error = '';
    $hit              = $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM {$table} WHERE email = %s LIMIT 1", $email ) );
    if ( '' !== $wpdb->last_error ) {
        return new WP_Error( 'wpses_suppress_check_failed', $wpdb->last_error );
    }
    return (bool) $hit;
}

/** Record a suppression. Returns true if the address is now on the list (freshly inserted
 *  OR already present), false if it could not be recorded (table unavailable, write error).
 *  The SNS handler turns a false into a 5xx so AWS redelivers rather than losing the bounce. */
function wpses_suppress( $email, $reason ) {
    global $wpdb;
    $email = strtolower( trim( (string) $email ) );
    if ( '' === $email ) {
        return false;
    }
    if ( true !== wpses_ensure_schema() ) {
        error_log( "[wp-ses-mail] cannot record suppression for {$email}: suppression table unavailable" );
        return false;
    }
    $table = wpses_suppress_table();
    // INSERT IGNORE: atomic, so concurrent bounces cannot lose each other's writes. Returns
    // 1 (inserted), 0 (already present, also fine), or false (a real write error).
    $result = $wpdb->query( $wpdb->prepare(
        "INSERT IGNORE INTO {$table} (email, reason, created_at) VALUES (%s, %s, %d)",
        $email,
        substr( (string) $reason, 0, 40 ),
        time()
    ) );
    if ( false === $result ) {
        error_log( "[wp-ses-mail] failed to write suppression for {$email}" );
        return false;
    }
    error_log( "[wp-ses-mail] suppressed {$email} ({$reason})" );
    return true;
}

function wpses_unsuppress( $email ) {
    global $wpdb;
    $email = strtolower( trim( (string) $email ) );
    return (int) $wpdb->delete( wpses_suppress_table(), array( 'email' => $email ) );
}

/* SES -> SNS -> here. Hard bounces and complaints only; a soft bounce is transient. */
add_action( 'rest_api_init', function () {
    register_rest_route( 'wpses/v1', '/sns', array(
        'methods'             => 'POST',
        'permission_callback' => '__return_true',   // SNS is unauthenticated; we verify topic + signature
        'callback'            => 'wpses_sns',
    ) );
} );

function wpses_sns( WP_REST_Request $req ) {
    $body = json_decode( $req->get_body(), true );
    if ( ! is_array( $body ) ) {
        return new WP_REST_Response( 'bad request', 400 );
    }

    // TOPIC PINNING, and it must come before trusting anything else.
    // A valid AWS signature only proves the message came from SOME SNS topic: AWS shares
    // one regional signing certificate across every customer's topics. Without pinning
    // the ARN, an attacker signs a Complaint for your users via their own topic and this
    // endpoint suppresses your users' mail. The TopicArn is a signed field, so a genuine
    // signature over a matching ARN cannot be forged without publishing to your topic.
    // Fail closed if the ARN is not configured: an unpinned endpoint is exploitable.
    if ( ! defined( 'WP_SES_SNS_TOPIC_ARN' ) || ! WP_SES_SNS_TOPIC_ARN ) {
        error_log( '[wp-ses-mail] SNS endpoint hit but WP_SES_SNS_TOPIC_ARN is unset; rejecting (fail closed).' );
        return new WP_REST_Response( 'endpoint not configured', 403 );
    }
    if ( ! isset( $body['TopicArn'] ) || ! hash_equals( (string) WP_SES_SNS_TOPIC_ARN, (string) $body['TopicArn'] ) ) {
        return new WP_REST_Response( 'wrong topic', 403 );
    }

    if ( ! wpses_sns_signature_ok( $body ) ) {
        return new WP_REST_Response( 'bad signature', 403 );
    }

    // From here the message is AUTHENTIC (topic + signature verified). A failure to act on
    // it must ask AWS to REDELIVER, not ack it away: a 200 tells SNS "handled", it never
    // retries, and the bounce (or the subscription) is lost, the address never suppressed,
    // WordPress keeps mailing it. So on any could-not-complete we return 5xx: SNS retries
    // (a transient blip recovers) or exhausts into the DLQ while raising
    // NumberOfNotificationsFailed (definitive: observable, not silent). Forged/wrong-topic
    // messages already returned 403 above and never reach this, so 5xx is never
    // attacker-inducible.
    if ( 'SubscriptionConfirmation' === ( $body['Type'] ?? '' ) ) {
        $res = wp_remote_get( $body['SubscribeURL'] ?? '', array( 'timeout' => 10 ) );
        if ( is_wp_error( $res ) || (int) wp_remote_retrieve_response_code( $res ) >= 400 ) {
            return new WP_REST_Response( 'could not confirm subscription; retry', 500 );
        }
        return new WP_REST_Response( 'subscribed', 200 );
    }

    $msg          = json_decode( $body['Message'] ?? '{}', true );
    $t            = $msg['notificationType'] ?? '';
    $recorded_all = true;

    if ( 'Bounce' === $t && 'Permanent' === ( $msg['bounce']['bounceType'] ?? '' ) ) {
        foreach ( $msg['bounce']['bouncedRecipients'] ?? array() as $r ) {
            $addr = $r['emailAddress'] ?? '';
            if ( '' === $addr ) {
                continue;   // malformed recipient: nothing to record, and a retry won't help
            }
            $recorded_all = wpses_suppress( $addr, 'hard bounce' ) && $recorded_all;
        }
    } elseif ( 'Complaint' === $t ) {
        foreach ( $msg['complaint']['complainedRecipients'] ?? array() as $r ) {
            $addr = $r['emailAddress'] ?? '';
            if ( '' === $addr ) {
                continue;
            }
            $recorded_all = wpses_suppress( $addr, 'complaint' ) && $recorded_all;
        }
    }

    if ( ! $recorded_all ) {
        error_log( '[wp-ses-mail] could not record a bounce/complaint; returning 500 so SNS retries.' );
        return new WP_REST_Response( 'could not record; retry', 500 );
    }
    return new WP_REST_Response( 'ok', 200 );
}

/** Verify the SNS message really came from AWS. Topic pinning (above) is the
 *  authorization; this is the authenticity. An endpoint that skips either lets anyone
 *  suppress your users' addresses. */
function wpses_sns_signature_ok( array $m ) {
    if ( empty( $m['SigningCertURL'] ) || empty( $m['Signature'] ) ) {
        return false;
    }
    $url = wp_parse_url( $m['SigningCertURL'] );
    if ( 'https' !== ( $url['scheme'] ?? '' ) ) {
        return false;
    }
    // Anchored: "sns.us-east-1.amazonaws.com.evil.com" must NOT pass.
    if ( ! preg_match( '/^sns\.[a-z0-9-]+\.amazonaws\.com$/', (string) ( $url['host'] ?? '' ) ) ) {
        return false;
    }
    // Cache the cert (the URL host is validated above, so the key is safe). SNS signing
    // certs are stable; refetching on every message adds a 5s-timeout round-trip.
    $cache_key = 'wpses_cert_' . md5( $m['SigningCertURL'] );
    $cert      = get_transient( $cache_key );
    if ( false === $cert ) {
        $cert = wp_remote_retrieve_body( wp_remote_get( $m['SigningCertURL'], array( 'timeout' => 5 ) ) );
        if ( $cert ) {
            set_transient( $cache_key, $cert, DAY_IN_SECONDS );
        }
    }
    $key = $cert ? openssl_get_publickey( $cert ) : false;
    if ( ! $key ) {
        return false;
    }
    $fields = ( 'Notification' === ( $m['Type'] ?? '' ) )
        ? array( 'Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type' )
        : array( 'Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type' );

    $canonical = '';
    foreach ( $fields as $f ) {
        if ( isset( $m[ $f ] ) ) {
            $canonical .= "{$f}\n{$m[$f]}\n";
        }
    }

    // SignatureVersion 1 is SHA1; version 2 is SHA256. AWS steers topics toward 2, and a
    // hardcoded SHA1 would reject every v2 message, dropping bounces silently, which is
    // the exact failure this plugin exists to prevent.
    $algo = ( '2' === (string) ( $m['SignatureVersion'] ?? '1' ) ) ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA1;

    return 1 === openssl_verify( $canonical, base64_decode( $m['Signature'] ), $key, $algo );
}

/* WP-CLI
 *   wp ses verify              region, credentials, identity, DKIM, sandbox, quota. EXITS NON-ZERO.
 *   wp ses unsuppress --email= remove an address from the suppression list (recovered mailbox)
 *
 * The point of `verify` is that it refuses to report success it has not earned. */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
    WP_CLI::add_command( 'ses verify', function () {
        $failed = false;

        $creds = wpses_credentials();
        if ( is_wp_error( $creds ) ) {
            WP_CLI::log( 'CREDENTIALS: ' . $creds->get_error_message() );
            WP_CLI::error( 'Cannot continue without credentials.' );  // exits 1
        }
        WP_CLI::log( 'Credentials: OK, source: ' . ( $creds['source'] ?? 'unknown' )
            . ' (nothing is stored). On an AWS host, a source of "env" means a stray AWS_* key is shadowing the role.' );

        $acct = wpses_api( 'GET', '/v2/email/account', '' );
        if ( is_wp_error( $acct ) ) {
            WP_CLI::error( 'SES unreachable: ' . $acct->get_error_message() );
        }
        if ( empty( $acct['ProductionAccessEnabled'] ) ) {
            WP_CLI::log( 'SANDBOX: this account can only send TO verified addresses. Request production access.' );
            $failed = true;
        }
        WP_CLI::log( sprintf(
            'Quota: %d / %d in the last 24h.',
            $acct['SendQuota']['SentLast24Hours'] ?? 0,
            $acct['SendQuota']['Max24HourSend'] ?? 0
        ) );

        // Prefer the domain identity (DKIM aligns for DMARC). If only the exact address
        // is verified, say so precisely rather than reporting a bare "not verified".
        $dom = substr( strrchr( WP_SES_FROM, '@' ), 1 );
        $id  = wpses_api( 'GET', '/v2/email/identities/' . rawurlencode( $dom ), '' );
        if ( ! is_wp_error( $id ) && ! empty( $id['VerifiedForSendingStatus'] ) ) {
            if ( 'SUCCESS' === ( $id['DkimAttributes']['Status'] ?? '' ) ) {
                WP_CLI::log( "Identity: {$dom} verified, DKIM active." );
            } else {
                WP_CLI::log( "DKIM: not enabled on {$dom}. Mail sends but will not align for DMARC." );
                $failed = true;
            }
        } else {
            $addr = wpses_api( 'GET', '/v2/email/identities/' . rawurlencode( WP_SES_FROM ), '' );
            if ( ! is_wp_error( $addr ) && ! empty( $addr['VerifiedForSendingStatus'] ) ) {
                WP_CLI::log( 'IDENTITY: the address ' . WP_SES_FROM . " is verified, but the domain {$dom} is not."
                    . ' Mail will send, but without domain DKIM it will not align for DMARC. Verify the domain for production.' );
                $failed = true;
            } else {
                WP_CLI::log( "IDENTITY: neither {$dom} nor " . WP_SES_FROM . ' is verified for sending in ' . WP_SES_REGION . '.' );
                $failed = true;
            }
        }

        if ( ! defined( 'WP_SES_SNS_TOPIC_ARN' ) || ! WP_SES_SNS_TOPIC_ARN ) {
            WP_CLI::log( 'BOUNCES: WP_SES_SNS_TOPIC_ARN is unset, so the bounce/complaint endpoint is disabled.'
                . ' You will not suppress bad addresses, which SES penalises. Set it for production.' );
            $failed = true;
        }

        // Assert the suppression table is really there, not just that dbDelta once ran.
        // Force a retry (bypass the negative cache) so verify reflects the true state now.
        $schema = wpses_ensure_schema( true );
        if ( false === $schema ) {
            WP_CLI::log( 'SUPPRESSION: the table is missing and could not be created, so sending is refused until fixed.'
                . ' Check the DB user has CREATE privilege.' );
            $failed = true;
        } elseif ( null === $schema ) {
            WP_CLI::log( 'SUPPRESSION: could not determine the table state (a DB error). Re-run once the database is healthy.' );
            $failed = true;
        }

        if ( $failed ) {
            WP_CLI::error( 'Not ready to send.' );  // exits 1, so `wp ses verify || alert` works
        }
        WP_CLI::success( 'SES is configured and ready.' );
    } );

    WP_CLI::add_command( 'ses unsuppress', function ( $args, $assoc ) {
        $email = $assoc['email'] ?? '';
        if ( ! $email ) {
            WP_CLI::error( 'Pass --email=address@example.com' );
        }
        WP_CLI::success( wpses_unsuppress( $email ) ? "Removed {$email}." : "{$email} was not on the list." );
    } );
}

/** Small signed GET/POST against the SES API, shared by the CLI checks. */
function wpses_api( $method, $path, $payload ) {
    $creds = wpses_credentials();
    if ( is_wp_error( $creds ) ) {
        return $creds;
    }
    $base = wpses_endpoint();
    $res  = wp_remote_request( $base . $path, array(
        'method'  => $method,
        'headers' => wpses_sigv4( $method, wpses_sig_host( $base ), $path, $payload, $creds ),
        'body'    => '' === $payload ? null : $payload,
        'timeout' => 15,
    ) );
    if ( is_wp_error( $res ) ) {
        return $res;
    }
    $body = json_decode( wp_remote_retrieve_body( $res ), true );
    if ( 200 !== (int) wp_remote_retrieve_response_code( $res ) ) {
        return new WP_Error( 'wpses_api', $body['message'] ?? 'SES API error' );
    }
    return $body;
}
