<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

/**
 * A user-to-chat binding as the identity store holds it.
 */
final class Identity
{
    public function __construct(
        public readonly string $userId,
        public readonly string $chatId,
        /** Unix timestamp of verification, or null when the link is not yet proven. */
        public readonly ?int $linkedAt = null,
    ) {
    }

    /**
     * Only a verified link counts as a second factor.
     *
     * A row carrying a chat id with no verification timestamp is a link that was
     * started and never completed. Treating it as linked is the mistake this
     * method exists to prevent: it would let anyone who can write a chat id into
     * the row satisfy a challenge.
     */
    public function isVerified(): bool
    {
        return $this->linkedAt !== null;
    }
}
