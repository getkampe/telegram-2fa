<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

use Kampe\TelegramTwoFactor\Results\Identity;

/**
 * Durable storage of the user-to-chat binding.
 *
 * Usually three columns on your users table. See SPEC.md section 2: both
 * directions of the mapping must be unique, and the uniqueness of chat_id must be
 * enforced by the database, not only by application code — without it one Telegram
 * account can become the second factor for many accounts.
 */
interface IdentityStore
{
    /**
     * The identity for an application user, or null when none is recorded.
     *
     * This may return an unverified identity (chat id present, linkedAt null);
     * callers decide whether that is acceptable.
     */
    public function findByUserId(string $userId): ?Identity;

    /**
     * The identity for a Telegram chat, or null when the chat is not known.
     */
    public function findByChatId(string $chatId): ?Identity;

    /**
     * Record a verified link between a user and a chat.
     *
     * Implementations must set the verification timestamp, and must fail rather
     * than overwrite when the chat is already linked to a different user.
     */
    public function link(string $userId, string $chatId): Identity;

    /**
     * Remove the link for a user. A user with no link is not an error.
     */
    public function unlink(string $userId): void;
}
