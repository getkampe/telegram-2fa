<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

/**
 * An account's Telegram enrollment, as the identity store holds it.
 *
 * This represents the row rather than only the linked state, so an account that
 * has been unlinked still has an Identity — carrying no chat, but carrying the
 * generation. That is deliberate: revocation has to outlive the binding it
 * revokes, or a token minted before an unlink would come back to life when the
 * user links again.
 */
final class Identity
{
    public function __construct(
        public readonly string $userId,
        /** The linked chat, or null when this account is not currently linked. */
        public readonly ?string $chatId = null,
        /** Unix timestamp of verification, or null when the link is not proven. */
        public readonly ?int $linkedAt = null,
        /**
         * Opaque enrollment generation, changed by every transition.
         *
         * Null only for a row that has never been enrolled. Anything holding
         * authority over an enrollment records this value and is void once it
         * differs — see TelegramTwoFactor::startChatReplacement.
         */
        public readonly ?string $generation = null,
    ) {
    }

    /**
     * Only a verified link counts as a second factor.
     *
     * A row carrying a chat id with no verification timestamp is a link that
     * was started and never completed. Treating it as linked is the mistake
     * this method exists to prevent: it would let anyone who can write a chat
     * id into the row satisfy a challenge.
     */
    public function isVerified(): bool
    {
        return $this->chatId !== null && $this->linkedAt !== null;
    }
}
