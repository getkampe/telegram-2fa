<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor;

use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;

/**
 * Validated configuration.
 *
 * The constructor rejects a configuration that cannot be secure, rather than
 * accepting it and logging a warning nobody reads. A missing webhook secret is the
 * clearest case: with one absent, the webhook is an open endpoint that will mint a
 * code for any chat id a stranger posts to it, and the application looks like it
 * works. Failing at boot is the only version of that outcome anyone notices.
 */
final class Config
{
    public function __construct(
        public readonly string $botToken,
        public readonly string $webhookSecret,
        /** Bot username without the @, needed to build t.me deeplinks. */
        public readonly ?string $botUsername = null,
        /** Name shown in bot messages. */
        public readonly string $appName = 'Kampe',
        public readonly int $codeLength = 6,
        public readonly int $codeTtl = 300,
        public readonly int $cooldown = 120,
        public readonly int $maxAttempts = 5,
        public readonly int $linkCodeLength = 8,
        public readonly int $linkTtl = 600,
        public readonly string $keyPrefix = 'tg2fa',
        public readonly string $hashAlgorithm = 'sha256',
        /** Pepper for code hashes. See Codes\CodeHasher. */
        public readonly string $hashPepper = '',
        /** Drop repeated update_ids. Telegram retries on timeout. */
        public readonly bool $dedupeUpdates = true,
        public readonly int $updateDedupeTtl = 3600,
        /** Reject webhook requests from outside Telegram's published ranges. */
        public readonly bool $restrictWebhookIps = false,
    ) {
        if (trim($this->botToken) === '') {
            throw new ConfigurationError(
                'A bot token is required. Create a bot with @BotFather and set TELEGRAM_BOT_TOKEN.'
            );
        }

        if (! preg_match('/^\d+:[A-Za-z0-9_-]{30,}$/', $this->botToken)) {
            throw new ConfigurationError(
                'The bot token is not in the format @BotFather issues (123456789:AA...). '
                . 'Check that the value was not truncated or quoted.'
            );
        }

        // Telegram accepts 1 to 256 characters here. One character would satisfy
        // Telegram and defeat the purpose, so the floor is ours, not theirs.
        if (! preg_match('/^[A-Za-z0-9_-]{32,256}$/', $this->webhookSecret)) {
            throw new ConfigurationError(
                'The webhook secret must be 32 to 256 characters of A-Z, a-z, 0-9, underscore or hyphen. '
                . 'Generate one with (new CodeGenerator)->webhookSecret() and set TELEGRAM_WEBHOOK_SECRET. '
                . 'This is what stops a stranger forging updates against your webhook; it is not optional.'
            );
        }

        if ($this->botUsername !== null && ! preg_match('/^[A-Za-z0-9_]{5,32}$/', $this->botUsername)) {
            throw new ConfigurationError(
                'The bot username must be 5 to 32 characters of A-Z, a-z, 0-9 or underscore, with no leading @.'
            );
        }

        if ($this->codeLength < 6 || $this->codeLength > 8) {
            throw new ConfigurationError('codeLength must be between 6 and 8.');
        }

        if ($this->codeTtl < 30 || $this->codeTtl > 600) {
            throw new ConfigurationError(
                'codeTtl must be between 30 and 600 seconds. A code that outlives the step it '
                . 'authorises is a code sitting in a chat history waiting to be reused.'
            );
        }

        if ($this->cooldown < 30) {
            throw new ConfigurationError(
                'cooldown must be at least 30 seconds, or the bot becomes a way to spam someone '
                . 'via your bot token.'
            );
        }

        if ($this->maxAttempts < 1 || $this->maxAttempts > 10) {
            throw new ConfigurationError(
                'maxAttempts must be between 1 and 10. Unlimited attempts against a six-digit '
                . 'code is not two-factor authentication.'
            );
        }

        if ($this->linkCodeLength < 8) {
            throw new ConfigurationError(
                'linkCodeLength must be at least 8. Paste-flow codes are stored under a key '
                . 'derived from the code, so they share one namespace across every user and a '
                . 'short code is enumerable.'
            );
        }

        if ($this->linkTtl < 60 || $this->linkTtl > 900) {
            throw new ConfigurationError('linkTtl must be between 60 and 900 seconds.');
        }

        if (! in_array($this->hashAlgorithm, hash_hmac_algos(), true)) {
            throw new ConfigurationError(
                sprintf('Unknown hash algorithm "%s".', $this->hashAlgorithm)
            );
        }

        if ($this->keyPrefix === '' || str_contains($this->keyPrefix, ':')) {
            throw new ConfigurationError('keyPrefix must be non-empty and must not contain a colon.');
        }
    }

    /**
     * Build from an array, applying defaults for anything absent.
     *
     * @param  array<string, mixed>  $values
     */
    public static function fromArray(array $values): self
    {
        $defaults = new \ReflectionClass(self::class);
        $params = $defaults->getConstructor()?->getParameters() ?? [];
        $args = [];

        foreach ($params as $param) {
            $name = $param->getName();
            $snake = strtolower((string) preg_replace('/([a-z\d])([A-Z])/', '$1_$2', $name));

            if (array_key_exists($name, $values)) {
                $args[$name] = $values[$name];
            } elseif (array_key_exists($snake, $values)) {
                $args[$name] = $values[$snake];
            } elseif ($param->isDefaultValueAvailable()) {
                $args[$name] = $param->getDefaultValue();
            }
        }

        /** @phpstan-ignore-next-line named arguments from a validated map */
        return new self(...$args);
    }

    public function key(string $kind, string $id): string
    {
        return sprintf('%s:%s:%s', $this->keyPrefix, $kind, $id);
    }

    public function deepLinkUrl(string $token): ?string
    {
        if ($this->botUsername === null) {
            return null;
        }

        return sprintf('https://t.me/%s?start=%s', $this->botUsername, $token);
    }
}
