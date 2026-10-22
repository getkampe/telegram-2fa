<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Results;

use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * The outcome of resolving a link token.
 */
final class LinkResult
{
    private function __construct(
        public readonly bool $ok,
        public readonly ?Identity $identity = null,
        public readonly ?ErrorCode $error = null,
    ) {
    }

    public static function linked(Identity $identity): self
    {
        return new self(true, $identity);
    }

    public static function failed(ErrorCode $error): self
    {
        return new self(false, null, $error);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ok' => $this->ok,
            'error' => $this->error?->value,
            'linked_at' => $this->identity?->linkedAt,
        ];
    }
}
