<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel\Console;

use Illuminate\Console\Command;
use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\Exceptions\TelegramTwoFactorException;

/**
 * A one-command answer to "is this thing configured correctly".
 */
final class TelegramStatusCommand extends Command
{
    protected $signature = 'telegram:status';

    protected $description = 'Check the Telegram 2FA configuration and bot connection';

    public function handle(): int
    {
        try {
            $config = $this->laravel->make(Config::class);
        } catch (TelegramTwoFactorException $e) {
            $this->error('Configuration rejected: ' . $e->getMessage());

            return self::FAILURE;
        }

        $this->info('Configuration accepted.');

        try {
            $me = $this->laravel->make(TelegramClient::class)->getMe();
        } catch (TelegramTwoFactorException $e) {
            $this->error('Could not reach Telegram: ' . $e->getMessage());

            return self::FAILURE;
        }

        $username = is_string($me['username'] ?? null) ? $me['username'] : null;

        $this->table(['Setting', 'Value'], [
            ['Bot', '@' . ($username ?? 'unknown')],
            ['Configured username', $config->botUsername ?? 'not set'],
            ['Deeplinks', $config->botUsername === null ? 'unavailable until bot_username is set' : 'available'],
            ['Code length', (string) $config->codeLength],
            ['Code TTL', $config->codeTtl . 's'],
            ['Cooldown', $config->cooldown . 's'],
            ['Max attempts', (string) $config->maxAttempts],
            ['Hash pepper', $config->hashPepper === '' ? 'not set' : 'set'],
            ['IP restriction', $config->restrictWebhookIps ? 'on' : 'off'],
        ]);

        if ($config->botUsername !== null && $username !== null && $config->botUsername !== $username) {
            $this->newLine();
            $this->warn(sprintf(
                'bot_username is "%s" but the token belongs to "@%s". Deeplinks will point at the wrong bot.',
                $config->botUsername,
                $username,
            ));

            return self::FAILURE;
        }

        if ($config->botUsername === null && $username !== null) {
            $this->newLine();
            $this->comment("Set TELEGRAM_BOT_USERNAME={$username} in .env to enable deeplinks.");
        }

        if ($config->hashPepper === '') {
            $this->newLine();
            $this->comment('TELEGRAM_2FA_HASH_PEPPER is not set. Set it so a dumped cache cannot be '
                . 'matched against a precomputed table of code hashes.');
        }

        return self::SUCCESS;
    }
}
