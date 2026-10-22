<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Support;

use Kampe\TelegramTwoFactor\Contracts\Logger;

/**
 * Discards everything. The default, so that the library never writes to a log
 * the host application did not hand it.
 */
final class NullLogger implements Logger
{
    public function info(string $message, array $context = []): void
    {
    }

    public function warning(string $message, array $context = []): void
    {
    }

    public function error(string $message, array $context = []): void
    {
    }
}
