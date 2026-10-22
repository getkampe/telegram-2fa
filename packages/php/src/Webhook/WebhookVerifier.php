<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Webhook;

use Kampe\TelegramTwoFactor\Config;

/**
 * Decides whether a request on the webhook endpoint really came from Telegram.
 *
 * This is the single most important check in the library. The webhook URL is
 * public and unauthenticated, and what it accepts is an assertion of the form
 * "this chat id is asking for a code". Without verification, anyone who learns
 * or guesses the URL can post an update carrying a chat id and have the bot mint
 * a code for whichever account that chat is linked to — and because the code then
 * arrives in the real owner's chat, nothing in the application looks wrong.
 *
 * Telegram supports this directly: register the webhook with a secret_token and
 * it sends that token in the X-Telegram-Bot-Api-Secret-Token header on every
 * request.
 */
final class WebhookVerifier
{
    /**
     * Telegram's published webhook source ranges.
     *
     * @see https://core.telegram.org/bots/webhooks
     */
    public const TELEGRAM_RANGES = ['149.154.160.0/20', '91.108.4.0/22'];

    public function __construct(private readonly Config $config)
    {
    }

    /**
     * @param  string|null  $headerValue  The X-Telegram-Bot-Api-Secret-Token header.
     * @param  string|null  $remoteIp     The connecting address, when IP restriction is on.
     */
    public function accepts(?string $headerValue, ?string $remoteIp = null): bool
    {
        if ($headerValue === null || $headerValue === '') {
            return false;
        }

        // hash_equals, so that the time taken to reject does not reveal how much
        // of the secret was right.
        if (! hash_equals($this->config->webhookSecret, $headerValue)) {
            return false;
        }

        if ($this->config->restrictWebhookIps && ! $this->fromTelegram($remoteIp)) {
            return false;
        }

        return true;
    }

    /**
     * Whether an address falls inside Telegram's published ranges.
     *
     * Only meaningful if $remoteIp is the real peer. Behind a load balancer or
     * CDN the peer is the proxy, and the client address comes from a header the
     * caller can set at will unless the proxy is configured as trusted — which
     * is why this check is off by default and the secret token is not.
     */
    public function fromTelegram(?string $remoteIp): bool
    {
        if ($remoteIp === null || filter_var($remoteIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return false;
        }

        foreach (self::TELEGRAM_RANGES as $range) {
            if ($this->inRange($remoteIp, $range)) {
                return true;
            }
        }

        return false;
    }

    private function inRange(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
