<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * The outcome of checking a submitted code.
 */
final class VerificationResult
{
    private function __construct(
        public readonly bool $ok,
        public readonly ?ErrorCode $error = null,
        /** Attempts left on the current code, where that is meaningful. */
        public readonly ?int $attemptsRemaining = null,
    ) {
    }

    public static function pass(): self
    {
        return new self(true);
    }

    public static function fail(ErrorCode $error, ?int $attemptsRemaining = null): self
    {
        return new self(false, $error, $attemptsRemaining);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ok' => $this->ok,
            'error' => $this->error?->value,
            'attempts_remaining' => $this->attemptsRemaining,
        ];
    }
}
