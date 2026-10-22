<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Results\Identity;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;

/**
 * An identity store that runs a second operation inside the first one's
 * transition, immediately before the compare-and-set is evaluated.
 *
 * That is the window the conditional transition exists to close: a caller has
 * validated some state, something else changes it, and the caller's write then
 * lands on state it never checked. Firing the hook here is deterministic — no
 * sleeps, no thread scheduling — and reproduces what two overlapping requests
 * would do against a shared database.
 */
final class InterleavingIdentityStore implements IdentityStore
{
    /** @var callable():void|null */
    private $hook = null;

    private bool $fired = false;

    public function __construct(private readonly ArrayIdentityStore $inner)
    {
    }

    public function inner(): ArrayIdentityStore
    {
        return $this->inner;
    }

    /**
     * Run $hook once, inside the next transition(), before it is evaluated.
     *
     * @param  callable():void  $hook
     */
    public function interleaveOnTransition(callable $hook): void
    {
        $this->hook = $hook;
        $this->fired = false;
    }

    public function findByUserId(string $userId): ?Identity
    {
        return $this->inner->findByUserId($userId);
    }

    public function findByChatId(string $chatId): ?Identity
    {
        return $this->inner->findByChatId($chatId);
    }

    public function transition(
        string $userId,
        ?string $chatId,
        ?string $expected,
        string $next,
    ): ?Identity {
        if (! $this->fired && $this->hook !== null) {
            $this->fired = true;
            ($this->hook)();
        }

        return $this->inner->transition($userId, $chatId, $expected, $next);
    }
}
