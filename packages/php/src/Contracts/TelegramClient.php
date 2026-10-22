<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * The slice of the Telegram Bot API this library needs.
 *
 * Kept deliberately small so it can be satisfied by the bundled curl client, by a
 * PSR-18 client, by an existing bot SDK already in the host application, or by a
 * fake in tests.
 */
interface TelegramClient
{
    /**
     * Send a message to a chat.
     *
     * @param  array<int, array<int, array<string, string>>>|null  $inlineKeyboard
     *         Rows of buttons, each button an array with text and callback_data.
     * @return bool True when Telegram accepted the message.
     */
    public function sendMessage(string $chatId, string $text, ?array $inlineKeyboard = null): bool;

    /**
     * Acknowledge a callback query so the client stops showing a spinner.
     */
    public function answerCallbackQuery(string $callbackQueryId, ?string $text = null): bool;

    /**
     * Bot identity, as returned by getMe. Keys: id, username, first_name.
     *
     * @return array<string, mixed>
     *
     * @throws \Kampe\TelegramTwoFactor\Exceptions\TelegramRequestFailed
     */
    public function getMe(): array;

    /**
     * Register the webhook URL with its secret token.
     *
     * The secret token is mandatory in this library: see SPEC.md section 7.1.
     */
    public function setWebhook(string $url, string $secretToken, ?array $allowedUpdates = null): bool;

    /**
     * Remove the registered webhook.
     */
    public function deleteWebhook(): bool;
}
