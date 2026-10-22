<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Telegram;

use Kampe\TelegramTwoFactor\Contracts\Messages;

/**
 * The bot's default English copy.
 *
 * Implement Contracts\Messages to translate or restyle any of it.
 */
class DefaultMessages implements Messages
{
    /**
     * Escape text for parse_mode HTML.
     *
     * Telegram's HTML mode needs only these three characters escaped. Any
     * implementation that interpolates a display name, an e-mail address or
     * anything else a user controls must run it through here first.
     */
    public static function escape(string $text): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $text);
    }

    public function code(string $code, int $ttlSeconds): string
    {
        return "🔐 <b>Verification code</b>\n\n"
            . "<code>{$code}</code>\n\n"
            . 'Valid for ' . $this->humanise($ttlSeconds) . ", once.\n"
            . 'If you did not ask for this, someone has your password. '
            . 'Do not enter the code, and change it now.';
    }

    public function linkInstructions(string $code, int $ttlSeconds, string $appName): string
    {
        $appName = self::escape($appName);

        return "🔗 <b>Link this chat to {$appName}</b>\n\n"
            . "<code>{$code}</code>\n\n"
            . "Enter this code on the Telegram setup page in your account settings.\n"
            . 'It expires in ' . $this->humanise($ttlSeconds) . '. Tap it to copy.';
    }

    public function linkSucceeded(string $accountLabel, string $appName): string
    {
        return '✅ <b>This chat is now your second factor for ' . self::escape($appName) . "</b>\n\n"
            . 'Account: ' . self::escape($accountLabel) . "\n\n"
            . "Send /code any time you need a verification code.\n"
            . 'If you did not do this, send /unlink immediately and change your password.';
    }

    public function linkTokenInvalid(): string
    {
        return "❌ <b>That code did not work</b>\n\n"
            . "It has expired, has already been used, or was mistyped.\n\n"
            . 'Start again from your account settings to get a fresh one.';
    }

    public function alreadyLinked(): string
    {
        return "ℹ️ <b>Already linked</b>\n\n"
            . "This chat is already set up as a second factor.\n\n"
            . 'Send /code for a verification code, or /unlink to remove it.';
    }

    public function notLinked(string $appName): string
    {
        return "🔌 <b>This chat is not linked</b>\n\n"
            . 'Open your ' . self::escape($appName) . " account settings and start the Telegram setup, "
            . 'then come back here.';
    }

    public function cooldown(int $secondsRemaining): string
    {
        return "⏳ <b>A code was just sent</b>\n\n"
            . 'Check the message above, or ask again in ' . $this->humanise($secondsRemaining) . '.';
    }

    public function unlinked(string $appName): string
    {
        return "🔓 <b>No longer your second factor</b>\n\n"
            . 'This chat has been unlinked from ' . self::escape($appName) . ".\n\n"
            . 'If you did not do this, your account may be compromised: sign in, change your '
            . 'password, and set up two-factor authentication again.';
    }

    public function welcome(bool $isLinked, string $appName): string
    {
        $appName = self::escape($appName);

        if ($isLinked) {
            return "👋 <b>{$appName} security bot</b>\n\n"
                . "This chat is linked and working.\n\n"
                . "/code — get a verification code\n"
                . "/status — show link details\n"
                . "/unlink — stop using this chat as a second factor\n"
                . '/help — this message';
        }

        return "👋 <b>{$appName} security bot</b>\n\n"
            . "I deliver verification codes for your {$appName} account.\n\n"
            . 'To get started, open your account settings, begin the Telegram setup, and follow '
            . "the link or code it gives you.\n\n"
            . '/help — this message';
    }

    public function unknownCommand(): string
    {
        return "🤔 <b>I do not know that command</b>\n\n"
            . 'Send /help to see what I can do.';
    }

    protected function humanise(int $seconds): string
    {
        if ($seconds < 60) {
            return $seconds . ' second' . ($seconds === 1 ? '' : 's');
        }

        $minutes = (int) round($seconds / 60);

        return $minutes . ' minute' . ($minutes === 1 ? '' : 's');
    }
}
