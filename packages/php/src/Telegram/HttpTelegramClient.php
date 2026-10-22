<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Telegram;

use Kampe\TelegramTwoFactor\Contracts\Logger;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\Exceptions\TelegramRequestFailed;
use Kampe\TelegramTwoFactor\Support\NullLogger;

/**
 * The default client: curl against api.telegram.org, no package dependencies.
 *
 * Substitute your own implementation of the contract to route through a PSR-18
 * client, a queue, or a bot SDK the host application already uses.
 */
final class HttpTelegramClient implements TelegramClient
{
    private const BASE = 'https://api.telegram.org/bot';

    private readonly Logger $logger;

    public function __construct(
        private readonly string $botToken,
        private readonly int $timeoutSeconds = 10,
        ?Logger $logger = null,
        private readonly string $parseMode = 'HTML',
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function sendMessage(string $chatId, string $text, ?array $inlineKeyboard = null): bool
    {
        $payload = [
            'chat_id' => $chatId,
            'text' => $text,
            'parse_mode' => $this->parseMode,
            'disable_web_page_preview' => true,
        ];

        if ($inlineKeyboard !== null) {
            $payload['reply_markup'] = json_encode(['inline_keyboard' => $inlineKeyboard], JSON_THROW_ON_ERROR);
        }

        try {
            $this->call('sendMessage', $payload);

            return true;
        } catch (TelegramRequestFailed $e) {
            // Delivery is fallible and the caller has a fallback path, so this
            // is reported rather than thrown. The message body is not logged:
            // for a challenge, the body is the code.
            $this->logger->error('telegram-2fa: sendMessage failed', [
                'reason' => $e->getMessage(),
            ]);

            return false;
        }
    }

    public function answerCallbackQuery(string $callbackQueryId, ?string $text = null): bool
    {
        $payload = ['callback_query_id' => $callbackQueryId];

        if ($text !== null) {
            $payload['text'] = $text;
        }

        try {
            $this->call('answerCallbackQuery', $payload);

            return true;
        } catch (TelegramRequestFailed) {
            return false;
        }
    }

    public function getMe(): array
    {
        /** @var array<string, mixed> $result */
        $result = $this->call('getMe', []);

        return $result;
    }

    public function setWebhook(string $url, string $secretToken, ?array $allowedUpdates = null): bool
    {
        if (! str_starts_with($url, 'https://')) {
            throw new TelegramRequestFailed(
                'Telegram will only deliver webhooks to an https URL with a valid certificate.'
            );
        }

        $payload = [
            'url' => $url,
            'secret_token' => $secretToken,
            // Telegram queues updates while a webhook is unset or failing. On a
            // first deploy that queue can hold stale /code requests, so it is
            // dropped rather than replayed into a live 2FA flow.
            'drop_pending_updates' => true,
        ];

        $payload['allowed_updates'] = json_encode(
            $allowedUpdates ?? ['message', 'callback_query'],
            JSON_THROW_ON_ERROR
        );

        $this->call('setWebhook', $payload);

        return true;
    }

    public function deleteWebhook(): bool
    {
        $this->call('deleteWebhook', ['drop_pending_updates' => true]);

        return true;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>|bool
     *
     * @throws TelegramRequestFailed
     */
    private function call(string $method, array $payload): array|bool
    {
        if (! function_exists('curl_init')) {
            throw new TelegramRequestFailed(
                'ext-curl is not available. Install it, or pass your own TelegramClient implementation.'
            );
        }

        $handle = curl_init(self::BASE . $this->botToken . '/' . $method);

        if ($handle === false) {
            throw new TelegramRequestFailed('Could not initialise a curl handle.');
        }

        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => min(5, $this->timeoutSeconds),
            // Explicit, because a Telegram bot token travelling over an
            // unverified connection is a bot token handed to whoever is in the
            // middle of it.
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);

        if ($body === false) {
            throw new TelegramRequestFailed('Telegram could not be reached: ' . $error);
        }

        /** @var array<string, mixed>|null $decoded */
        $decoded = json_decode((string) $body, true);

        if (! is_array($decoded)) {
            throw new TelegramRequestFailed(
                sprintf('Telegram returned a non-JSON response with status %d.', $status)
            );
        }

        if (($decoded['ok'] ?? false) !== true) {
            // description is Telegram's own error text; it does not echo the
            // message body back, so it is safe to surface.
            throw new TelegramRequestFailed(sprintf(
                'Telegram rejected %s with status %d: %s',
                $method,
                $status,
                is_string($decoded['description'] ?? null) ? $decoded['description'] : 'no description',
            ));
        }

        $result = $decoded['result'] ?? true;

        return is_array($result) ? $result : (bool) $result;
    }
}
