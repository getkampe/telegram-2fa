<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * The outcome of asking for a code to be issued and delivered.
 *
 * Note what is absent: the code. Neither challenge direction returns it. The code
 * exists inside the library for exactly as long as it takes to hash it into the
 * store and hand it to Telegram, which is the only reason a result object like
 * this can be returned straight to an HTTP client without redacting anything.
 */
final class ChallengeResult
{
    private function __construct(
        public readonly bool $ok,
        public readonly ?ErrorCode $error = null,
        /** Unix timestamp at which the issued code stops being accepted. */
        public readonly ?int $expiresAt = null,
        /** Unix timestamp at which another code may be requested. */
        public readonly ?int $nextSendAt = null,
    ) {
    }

    public static function sent(int $expiresAt, int $nextSendAt): self
    {
        return new self(true, null, $expiresAt, $nextSendAt);
    }

    public static function failed(ErrorCode $error, ?int $nextSendAt = null): self
    {
        return new self(false, $error, null, $nextSendAt);
    }

    /**
     * Seconds the caller should wait before offering a resend, never negative.
     */
    public function retryAfter(int $now): int
    {
        return $this->nextSendAt === null ? 0 : max(0, $this->nextSendAt - $now);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ok' => $this->ok,
            'error' => $this->error?->value,
            'expires_at' => $this->expiresAt,
            'next_send_at' => $this->nextSendAt,
        ];
    }
}
