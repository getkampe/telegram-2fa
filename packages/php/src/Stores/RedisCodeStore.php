<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Contracts\RedisCommands;

/**
 * The canonical code store on Redis: JSON on the wire, atomicity in the server.
 *
 * Use this one. CacheCodeStore works, and works only for a deployment where
 * every process that touches these keys is PHP:
 *
 * - **Encoding.** Laravel's Redis cache runs values through serialize(), so an
 *   array lands in Redis as `a:6:{s:4:"hash";...}`. Every other implementation
 *   of this protocol reads and writes JSON, so a record written through the
 *   cache is unreadable to them and theirs is unreadable to it. The shared
 *   fixtures in /conformance did not catch this, because they check the shape
 *   of a record rather than the bytes an adapter puts on the wire.
 * - **Atomicity.** CacheCodeStore serialises its take behind Laravel's own
 *   named lock. That is sound between PHP processes and meaningless to a Node
 *   or Go process, which issues GETDEL and knows nothing about the lock — so a
 *   locked GET-then-DEL can interleave with it and the same code is accepted
 *   twice.
 *
 * This class fixes both by doing what the specification actually says: values
 * are the JSON of SPEC.md section 9, and single use rests on one server-side
 * operation that every client in every language performs identically.
 *
 * **What it does not fix.** Going through a connection removes the *cache's*
 * serialization and nothing else. The client itself still has options, and
 * Laravel sets them straight from config: a serializer or compression setting
 * wraps every value before it reaches Redis, and a key prefix — which a default
 * Laravel application sets from REDIS_PREFIX — means the record this stores as
 * `tg2fa:code:user-1` physically lives at `<prefix>tg2fa:code:user-1`, where no
 * other implementation will look for it. The adapters check for all three at
 * construction; see RedisClientOptions for what is refused and what can be
 * acknowledged.
 *
 * So the physical keys match across languages only if the client applies no
 * prefix of its own, or every client applies the same one. Namespacing belongs
 * in Config::$keyPrefix, which every implementation honours and which is part of
 * the key the specification describes.
 *
 * TTLs are Redis's own, which is why each record also carries its own
 * expires_at: the two must agree, and the explicit field is what keeps expiry
 * correct against a replica whose clock has drifted.
 */
final class RedisCodeStore implements CodeStore
{
    public function __construct(private readonly RedisCommands $redis) {}

    public function get(string $key): mixed
    {
        return $this->decode($this->redis->get($key));
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->redis->set($key, $this->encode($value), $ttlSeconds);
    }

    public function forget(string $key): void
    {
        $this->redis->delete($key);
    }

    /**
     * Atomically read a value and remove it.
     *
     * Exactly one caller may receive a given value, and the guarantee is the
     * server's rather than this process's, so it holds across languages and
     * across machines.
     */
    public function take(string $key): mixed
    {
        return $this->decode($this->redis->getDelete($key));
    }

    /**
     * Atomically write only if the key is absent, reporting whether it did.
     *
     * SET NX. The boolean makes the write itself the check, which is how the
     * cooldown and the webhook's idempotency claim become a reservation exactly
     * one caller can win.
     */
    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        return $this->redis->set($key, $this->encode($value), $ttlSeconds, true);
    }

    /**
     * JSON, with no PHP-specific flags that would change the bytes.
     *
     * JSON_THROW_ON_ERROR rather than a silent false: a record this library
     * cannot encode is a bug here, not a condition to paper over at runtime.
     */
    private function encode(mixed $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Decode, treating anything unreadable as absent.
     *
     * A key holding something this library did not write — a collision with
     * another application's prefix, or a record left by the cache-backed store
     * before a migration — must not throw from inside a verification path.
     * Absent is the safe reading, and the caller's own re-validation against the
     * enrollment generation catches the rest.
     */
    private function decode(?string $raw): mixed
    {
        if ($raw === null || $raw === '') {
            return null;
        }

        try {
            return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
    }
}
