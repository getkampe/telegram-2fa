<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * Wall clock, injectable so that expiry and cooldown are testable without sleeping.
 */
interface Clock
{
    /**
     * Current unix timestamp in seconds.
     */
    public function now(): int;
}
