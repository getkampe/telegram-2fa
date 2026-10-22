<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * Every piece of text the bot sends, in one place.
 *
 * Implement this to translate the bot, or to match your own tone. The default
 * implementation is Telegram\DefaultMessages.
 *
 * All returned strings are sent with parse_mode HTML, so an implementation that
 * interpolates user-supplied text must escape it first — see
 * Telegram\DefaultMessages::escape. Unescaped interpolation of a display name
 * containing a left angle bracket produces a message Telegram rejects outright,
 * which is the benign case; the interesting case is a crafted name that closes
 * your tag and opens an anchor.
 */
interface Messages
{
    /**
     * A freshly issued 2FA code, delivered to the user's chat.
     */
    public function code(string $code, int $ttlSeconds): string;

    /**
     * Instructions carrying a paste-flow link code.
     */
    public function linkInstructions(string $code, int $ttlSeconds, string $appName): string;

    /**
     * Confirmation that the chat is now a second factor for an account.
     *
     * $accountLabel is whatever the host application chose to identify the
     * account by. Prefer something partially masked: this message lands in a
     * chat that may be read over someone's shoulder.
     */
    public function linkSucceeded(string $accountLabel, string $appName): string;

    public function linkTokenInvalid(): string;

    public function alreadyLinked(): string;

    public function notLinked(string $appName): string;

    /**
     * Sent when a code is requested again inside the cooldown window.
     */
    public function cooldown(int $secondsRemaining): string;

    /**
     * How to remove the factor, in answer to /unlink.
     *
     * The bot does not perform the removal: whoever holds the phone can
     * already read the codes, and letting them also remove the factor with no
     * session and no password turns a stolen phone into a permanently
     * single-factor account. So this explains where to do it instead — which
     * is a real answer, unlike the generic menu.
     */
    public function unlinkInstructions(string $appName): string;

    /**
     * Notice that this chat is no longer a second factor.
     */
    public function unlinked(string $appName): string;

    /**
     * Response to /start with no payload, and to /help.
     */
    public function welcome(bool $isLinked, string $appName): string;

    public function unknownCommand(): string;
}
