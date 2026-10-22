<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Support;

use Kampe\TelegramTwoFactor\Contracts\Logger;

/**
 * Adapts any PSR-3 logger, without taking a hard dependency on psr/log.
 *
 * The constructor accepts anything with info, warning and error methods, which
 * every PSR-3 implementation has.
 */
final class PsrLogger implements Logger
{
    public function __construct(private readonly object $psr)
    {
    }

    public function info(string $message, array $context = []): void
    {
        $this->psr->info($message, $context); // @phpstan-ignore-line
    }

    public function warning(string $message, array $context = []): void
    {
        $this->psr->warning($message, $context); // @phpstan-ignore-line
    }

    public function error(string $message, array $context = []): void
    {
        $this->psr->error($message, $context); // @phpstan-ignore-line
    }
}
