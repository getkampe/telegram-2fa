<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Contracts\RedisCommands;
use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;

/**
 * RedisCommands over ext-redis (the \Redis class from phpredis).
 *
 * The connection is yours: this class never connects, selects a database or
 * sets a prefix, so it inherits whatever the application already configured.
 */
final class PhpRedisCommands implements RedisCommands
{
    /**
     * GET and DEL in one round trip, for servers older than Redis 6.2, which
     * have no GETDEL. EVAL runs the whole script atomically, so the guarantee
     * is the same.
     */
    public const TAKE_SCRIPT = <<<'LUA'
        local v = redis.call('GET', KEYS[1])
        if v then redis.call('DEL', KEYS[1]) end
        return v
        LUA;

    private readonly bool $hasGetDel;

    /**
     * @param  object  $redis  A \Redis, or anything with the same methods.
     * @param  bool|null  $hasGetDel  Force the GETDEL path on or off. Null
     *                                detects it, which costs one INFO call.
     */
    public function __construct(
        private readonly object $redis,
        ?bool $hasGetDel = null,
    ) {
        foreach (['get', 'set', 'del', 'eval'] as $method) {
            if (! method_exists($this->redis, $method)) {
                throw new ConfigurationError(sprintf(
                    'The Redis client %s has no %s() method, so this adapter cannot use it. '
                    . 'Pass a \Redis from ext-redis, or implement RedisCommands yourself.',
                    $this->redis::class,
                    $method,
                ));
            }
        }

        $this->hasGetDel = $hasGetDel ?? $this->detectGetDel();
    }

    public function get(string $key): ?string
    {
        $value = $this->redis->get($key);

        // phpredis returns false for a missing key.
        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttlSeconds, bool $onlyIfAbsent = false): bool
    {
        $options = ['EX' => $ttlSeconds];

        if ($onlyIfAbsent) {
            $options[] = 'NX';
        }

        // phpredis returns false when NX declines, and true otherwise. Both
        // falsey forms are treated as a refusal because a client that reports a
        // lost reservation as won leaves no cooldown at all.
        return $this->redis->set($key, $value, $options) === true;
    }

    public function delete(string $key): void
    {
        $this->redis->del($key);
    }

    public function getDelete(string $key): ?string
    {
        $value = $this->hasGetDel
            ? $this->redis->getDel($key)
            : $this->redis->eval(self::TAKE_SCRIPT, [$key], 1);

        return is_string($value) ? $value : null;
    }

    /**
     * Whether the server has GETDEL, which arrived in Redis 6.2.
     *
     * Detected rather than assumed, and the fallback is a script rather than
     * two calls, so an older server is slower by one Lua compile and not less
     * correct.
     */
    private function detectGetDel(): bool
    {
        if (! method_exists($this->redis, 'getDel')) {
            return false;
        }

        try {
            /** @var array<string, mixed>|false $info */
            $info = $this->redis->info('SERVER');
        } catch (\Throwable) {
            return false;
        }

        $version = is_array($info) ? ($info['redis_version'] ?? null) : null;

        if (! is_string($version)) {
            return false;
        }

        return version_compare($version, '6.2.0', '>=');
    }
}
