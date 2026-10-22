<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * Short-lived key/value storage with a TTL.
 *
 * Any cache with expiry satisfies this: Redis, Memcached, APCu, a database table
 * with an expires_at column. The store holds code hashes, never plaintext codes,
 * so a store compromise does not yield usable codes.
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
}
