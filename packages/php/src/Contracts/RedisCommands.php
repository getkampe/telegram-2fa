<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

/**
 * The Redis commands RedisCodeStore needs, as a contract your client implements.
 *
 * Four methods, so the package depends on no particular Redis client. Adapters
 * for ext-redis and for Laravel's connection ship with it; anything else is a
 * dozen lines.
 *
 * Every method here is a single server round trip, and that is the whole point.
 * A take built from a GET followed by a DEL in the client lets two simultaneous
 * verifications of one code both succeed, and no amount of locking in one
 * language fixes it when another language is reading the same keys — see the
 * class comment on RedisCodeStore.
 */
interface RedisCommands
{
    /**
     * GET. Null when the key is absent.
     */
    public function get(string $key): ?string;

    /**
     * SET key value EX $ttlSeconds, with NX when $onlyIfAbsent.
     *
     * @return bool Whether the value was stored. False only ever means NX
     *              declined — and it must mean that: a client that reports a
     *              refusal as success turns the cooldown into no cooldown at all
     *              and makes the webhook process an update twice.
     */
    public function set(string $key, string $value, int $ttlSeconds, bool $onlyIfAbsent = false): bool;

    /**
     * DEL.
     */
    public function delete(string $key): void;

    /**
     * GETDEL, or EVAL of a GET-then-DEL script on servers older than Redis 6.2.
     *
     * One round trip, server side. Two calls from the client is the bug this
     * interface exists to prevent, and an adapter that does that compiles and
     * passes every single-threaded test — so the obligation is stated here
     * rather than implied.
     */
    public function getDelete(string $key): ?string;
}
