<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Contracts\CodeStore;

/**
 * A store that runs a second request in the middle of the first one's
 * read-modify-write, which is where a race lives.
 *
 * PHP cannot start a thread here, but it does not need to: the bug is that the
 * sequence has an interleaving point at all. This wrapper opens that point
 * deliberately — the hook fires while the first caller is between reading a
 * record and writing its decision back — so a non-atomic implementation shows
 * the same double-success it would show under two real requests.
 */
final class InterleavingCodeStore implements CodeStore
{
    /** @var callable():void|null */
    private $hook = null;

    private string $hookKey = '';

    private bool $fired = false;

    public function __construct(private readonly CodeStore $inner)
    {
    }

    /**
     * Run $hook once, inside the next take() of a key starting with $keyPrefix,
     * after the value has been removed and before the caller receives it.
     *
     * A prefix rather than an exact key, so that a test can target the link
     * record — whose key is a hash of a token the library never exposes —
     * without reimplementing the derivation and coupling itself to it.
     *
     * @param  callable():void  $hook
     */
    public function interleaveOnTake(string $keyPrefix, callable $hook): void
    {
        $this->hookKey = $keyPrefix;
        $this->hook = $hook;
        $this->fired = false;
    }

    /**
     * Run $hook once, inside the next add() of a matching key, before it is
     * attempted — the window a check-then-write cooldown would lose.
     *
     * @param  callable():void  $hook
     */
    public function interleaveOnAdd(string $keyPrefix, callable $hook): void
    {
        $this->hookKey = $keyPrefix;
        $this->hook = $hook;
        $this->fired = false;
    }

    public function get(string $key): mixed
    {
        return $this->inner->get($key);
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->inner->put($key, $value, $ttlSeconds);
    }

    public function forget(string $key): void
    {
        $this->inner->forget($key);
    }

    public function take(string $key): mixed
    {
        $value = $this->inner->take($key);

        $this->maybeFire($key);

        return $value;
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        $this->maybeFire($key);

        return $this->inner->add($key, $value, $ttlSeconds);
    }

    private function maybeFire(string $key): void
    {
        if ($this->fired || $this->hook === null || ! str_starts_with($key, $this->hookKey)) {
            return;
        }

        $this->fired = true;
        ($this->hook)();
    }
}
