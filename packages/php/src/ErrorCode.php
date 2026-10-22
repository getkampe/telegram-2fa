<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor;

/**
 * The error vocabulary of SPEC.md section 10.
 *
 * These identifiers are part of the protocol, not an implementation detail: a
 * client written against them works against any conforming implementation in any
 * language. The string values are the wire form and must not be changed.
 */
enum ErrorCode: string
{
    /** The account has no verified Telegram link. */
    case NotLinked = 'not_linked';

    /** The account, or the chat, is already linked. */
    case AlreadyLinked = 'already_linked';

    /** A code was sent too recently. The result carries the next send time. */
    case Cooldown = 'cooldown';

    /** Telegram did not accept the message. */
    case SendFailed = 'send_failed';

    /** The submitted code does not match. */
    case Invalid = 'invalid';

    /** No live code for this account: never issued, aged out, or already used. */
    case Expired = 'expired';

    /** The attempt budget for this code is exhausted and the code is now dead. */
    case TooManyAttempts = 'too_many_attempts';

    /** Link token unknown, expired or already used. */
    case InvalidToken = 'invalid_token';

    /** Webhook secret token missing or wrong. */
    case WebhookUnauthorized = 'webhook_unauthorized';

    /**
     * A message safe to show an end user.
     *
     * Deliberately vague about which of "never issued", "expired" and "already
     * used" applies, because distinguishing them tells an attacker holding a
     * session whether a challenge is in flight.
     */
    public function message(): string
    {
        return match ($this) {
            self::NotLinked => 'No Telegram account is linked to this profile.',
            self::AlreadyLinked => 'This Telegram account is already linked.',
            self::Cooldown => 'A code was just sent. Please wait before requesting another.',
            self::SendFailed => 'The code could not be delivered. Please try again or use another method.',
            self::Invalid => 'That code is not valid.',
            self::Expired => 'That code is no longer valid. Request a new one.',
            self::TooManyAttempts => 'Too many incorrect attempts. Request a new code.',
            self::InvalidToken => 'This link has expired or has already been used.',
            self::WebhookUnauthorized => 'Unauthorized.',
        };
    }
}
