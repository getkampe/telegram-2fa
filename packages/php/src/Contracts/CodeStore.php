<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * Short-lived key/value storage with a TTL.
 *
 * Any cache with expiry can satisfy this: Redis, Memcached, APCu, a database
 * table with an expires_at column. The store holds code hashes, never plaintext
 * codes, so a store compromise does not yield usable codes.
 *
 * Two of the five methods must be atomic. They are not a convenience: a
 * verification built from get-check-forget is a time-of-check-to-time-of-use
 * race, and two requests arriving together both read the live record, both match
 * it, and both succeed — so a single-use code is used twice, and the attempt
 * counter loses increments to the same lost-update race. Single use and the
 * attempt budget are the two things standing between a six-digit code and an
 * attacker, so they cannot rest on a sequence the store is free to interleave.
 */
interface CodeStore
{
    /**
     * Read a value. Returns null when the key is absent or expired.
     */
    public function get(string $key): mixed;

    /**
     * Write a value with a time to live in seconds.
     */
    public function put(string $key, mixed $value, int $ttlSeconds): void;

    /**
     * Remove a key. A missing key is not an error.
     */
    public function forget(string $key): void;

    /**
     * Atomically read a value and remove it, returning null when absent.
     *
     * Exactly one caller may receive a given value. This is what makes a code
     * single-use under concurrency: the winner holds the only copy and either
     * accepts it or writes it back with one more attempt spent, while every
     * other concurrent caller sees nothing.
     *
     * Redis has GETDEL (6.2+) or EVAL; Laravel's cache has pull(); a SQL store
     * can DELETE ... RETURNING, or SELECT FOR UPDATE inside a transaction.
     */
    public function take(string $key): mixed;

    /**
     * Atomically write a value only if the key is absent.
     *
     * @return bool True when this call stored the value, false when a value was
     *              already present. The boolean is the point: it makes the
     *              write a reservation that exactly one caller can win, which is
     *              how the cooldown and the webhook's idempotency claim avoid
     *              check-then-write races.
     *
     * Redis has SET NX EX; Laravel's cache has add(); Memcached has add().
     */
    public function add(string $key, mixed $value, int $ttlSeconds): bool;
}
