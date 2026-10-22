<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Contracts\TelegramClient;

final class FakeTelegramClient implements TelegramClient
{
    /** @var array<int, array{chat_id: string, text: string}> */
    public array $sent = [];

    /** @var array<int, string> */
    public array $answeredCallbacks = [];

    public bool $shouldFailSending = false;

    public function sendMessage(string $chatId, string $text, ?array $inlineKeyboard = null): bool
    {
        if ($this->shouldFailSending) {
            return false;
        }

        $this->sent[] = ['chat_id' => $chatId, 'text' => $text];

        return true;
    }

    public function answerCallbackQuery(string $callbackQueryId, ?string $text = null): bool
    {
        $this->answeredCallbacks[] = $callbackQueryId;

        return true;
    }

    public function getMe(): array
    {
        return ['id' => 1, 'username' => 'kampe_test_bot', 'first_name' => 'Kampe'];
    }

    public function setWebhook(string $url, string $secretToken, ?array $allowedUpdates = null): bool
    {
        return true;
    }

    public function deleteWebhook(): bool
    {
        return true;
    }

    public function lastMessage(): ?string
    {
        $last = end($this->sent);

        return $last === false ? null : $last['text'];
    }

    public function lastSentTo(): ?string
    {
        $last = end($this->sent);

        return $last === false ? null : $last['chat_id'];
    }

    public function messageCount(): int
    {
        return count($this->sent);
    }

    public function reset(): void
    {
        $this->sent = [];
        $this->answeredCallbacks = [];
    }
}
