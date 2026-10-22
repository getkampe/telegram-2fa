<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

/**
 * A pending link, ready to be shown to the user.
 *
 * This is the one place a secret legitimately leaves the library, because the user
 * has to receive it somehow. For the deeplink flow put $url in a button or a QR
 * code; for the paste flow show $token in the chat. Either way it does not belong
 * in a log line or an audit record.
 */
final class LinkRequest
{
    public function __construct(
        /** The link token: a deeplink nonce, or a short code for the paste flow. */
        public readonly string $token,
        /** Unix timestamp after which the token stops resolving. */
        public readonly int $expiresAt,
        /** t.me deeplink, present only when the bot username is known. */
        public readonly ?string $url = null,
    ) {
    }
}
