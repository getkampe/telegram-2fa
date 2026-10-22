<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel\Console;

use Illuminate\Console\Command;
use Kampe\TelegramTwoFactor\Codes\CodeGenerator;
use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\Exceptions\TelegramRequestFailed;

final class SetWebhookCommand extends Command
{
    protected $signature = 'telegram:webhook
        {--url= : The webhook URL. Defaults to the configured path on APP_URL.}
        {--generate-secret : Print a fresh secret token and exit without calling Telegram.}
        {--delete : Remove the registered webhook.}';

    protected $description = 'Register, inspect or remove the Telegram webhook';

    public function handle(): int
    {
        if ($this->option('generate-secret')) {
            $this->line((new CodeGenerator())->webhookSecret());
            $this->newLine();
            $this->comment('Put this in .env as TELEGRAM_WEBHOOK_SECRET, then run this command again without the flag.');

            return self::SUCCESS;
        }

        // Resolving Config validates the whole environment, so a missing token
        // or secret is reported here rather than at the first real request.
        $config = $this->laravel->make(Config::class);
        $client = $this->laravel->make(TelegramClient::class);

        if ($this->option('delete')) {
            $client->deleteWebhook();
            $this->info('Webhook removed. The bot will not receive updates until you set it again.');

            return self::SUCCESS;
        }

        $url = (string) ($this->option('url') ?: rtrim((string) config('app.url'), '/')
            . '/' . ltrim((string) config('telegram-2fa.webhook_path', 'telegram/webhook'), '/'));

        try {
            $client->setWebhook($url, $config->webhookSecret);
        } catch (TelegramRequestFailed $e) {
            $this->error($e->getMessage());

            if (str_contains($e->getMessage(), 'https')) {
                $this->newLine();
                $this->comment('Telegram only delivers to https with a certificate it trusts. For local work, '
                    . 'expose your app through a tunnel and pass that URL with --url.');
            }

            return self::FAILURE;
        }

        $this->info('Webhook registered.');
        $this->table(['Setting', 'Value'], [
            ['URL', $url],
            ['Secret token', str_repeat('*', 8) . ' (' . strlen($config->webhookSecret) . ' chars)'],
            ['Allowed updates', 'message, callback_query'],
        ]);

        return self::SUCCESS;
    }
}
