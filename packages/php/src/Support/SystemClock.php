<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Support;

use Kampe\TelegramTwoFactor\Contracts\Clock;

final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}
