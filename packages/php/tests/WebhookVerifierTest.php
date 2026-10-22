<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Webhook\WebhookVerifier;

/**
 * SPEC.md section 7. The check that matters most: without it the webhook accepts
 * a forged assertion that any chat id is asking for a code.
 */
final class WebhookVerifierTest extends TestCase
{
    public function test_the_matching_secret_is_accepted(): void
    {
        $verifier = new WebhookVerifier($this->config);

        $this->assertTrue($verifier->accepts(str_repeat('s', 48)));
    }

    public function test_a_wrong_secret_is_rejected(): void
    {
        $verifier = new WebhookVerifier($this->config);

        $this->assertFalse($verifier->accepts(str_repeat('x', 48)));
    }

    public function test_a_missing_secret_is_rejected(): void
    {
        $verifier = new WebhookVerifier($this->config);

        $this->assertFalse($verifier->accepts(null));
        $this->assertFalse($verifier->accepts(''));
    }

    /**
     * A prefix of the real secret must not be accepted. Length-insensitive or
     * truncating comparisons are the classic way this check gets written wrong.
     */
    public function test_a_prefix_of_the_secret_is_rejected(): void
    {
        $verifier = new WebhookVerifier($this->config);

        $this->assertFalse($verifier->accepts(str_repeat('s', 47)));
        $this->assertFalse($verifier->accepts(str_repeat('s', 49)));
    }

    public function test_ip_restriction_accepts_telegram_ranges(): void
    {
        $verifier = new WebhookVerifier($this->config(['restrict_webhook_ips' => true]));
        $secret = str_repeat('s', 48);

        $this->assertTrue($verifier->accepts($secret, '149.154.160.1'));
        $this->assertTrue($verifier->accepts($secret, '149.154.175.254'));
        $this->assertTrue($verifier->accepts($secret, '91.108.4.10'));
    }

    public function test_ip_restriction_rejects_everything_else(): void
    {
        $verifier = new WebhookVerifier($this->config(['restrict_webhook_ips' => true]));
        $secret = str_repeat('s', 48);

        $this->assertFalse($verifier->accepts($secret, '8.8.8.8'));
        $this->assertFalse($verifier->accepts($secret, '149.154.176.1'));
        $this->assertFalse($verifier->accepts($secret, '127.0.0.1'));
        $this->assertFalse($verifier->accepts($secret, null));
        $this->assertFalse($verifier->accepts($secret, 'not-an-ip'));
    }

    public function test_ip_restriction_is_off_by_default(): void
    {
        $verifier = new WebhookVerifier($this->config);

        // Off by default because behind a proxy the peer address is the proxy,
        // so the check would be either useless or actively misleading.
        $this->assertTrue($verifier->accepts(str_repeat('s', 48), '8.8.8.8'));
    }
}
