<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Support;

use Kampe\TelegramTwoFactor\Contracts\Clock;

/**
 * A clock that only moves when you move it.
 *
 * Shipped in src rather than tests so that applications can test their own
 * expiry and cooldown handling without sleeping through it.
 */
final class FrozenClock implements Clock
{
    public function __construct(private int $now = 1_700_000_000)
    {
    }

    public function now(): int
    {
        return $this->now;
    }

    public function advance(int $seconds): self
    {
        $this->now += $seconds;

        return $this;
    }

    public function setTo(int $timestamp): self
    {
        $this->now = $timestamp;

        return $this;
    }
}
