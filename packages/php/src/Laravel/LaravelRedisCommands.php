<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Contracts\Redis\Connection;
use Kampe\TelegramTwoFactor\Contracts\RedisCommands;
use Kampe\TelegramTwoFactor\Stores\PhpRedisCommands;

/**
 * RedisCommands over an Illuminate Redis connection.
 *
 * Deliberately the connection and not the cache repository. The cache
 * repository serialises values with PHP's serialize(), which is what makes
 * records written through Laravel's cache unreadable to every other
 * implementation of this protocol — see the class comment on RedisCodeStore.
 * Going through the connection means the bytes are exactly the JSON this
 * library produced.
 *
 * Laravel's own key prefix does not apply at this level either, which is a
 * feature: the keys are the ones SPEC.md section 9 specifies, so the other
 * implementations find them where the specification says they are.
 *
 *     $store = new RedisCodeStore(
 *         new LaravelRedisCommands(Redis::connection())
 *     );
 */
final class LaravelRedisCommands implements RedisCommands
{
    private readonly bool $hasGetDel;

    /**
     * @param  Connection  $connection  From Redis::connection().
     * @param  bool|null  $hasGetDel  Force the GETDEL path on or off. Null
     *                                detects it, which costs one INFO call.
     */
    public function __construct(
        private readonly Connection $connection,
        ?bool $hasGetDel = null,
    ) {
        $this->hasGetDel = $hasGetDel ?? $this->detectGetDel();
    }

    public function get(string $key): ?string
    {
        $value = $this->connection->command('get', [$key]);

        return is_string($value) ? $value : null;
    }

    public function set(string $key, string $value, int $ttlSeconds, bool $onlyIfAbsent = false): bool
    {
        $arguments = [$key, $value, 'EX', $ttlSeconds];

        if ($onlyIfAbsent) {
            $arguments[] = 'NX';
        }

        $result = $this->connection->command('set', $arguments);

        // phpredis answers true/false; predis answers a Status object whose
        // payload is OK, or null when NX declines. Anything that is not an
        // affirmative is treated as a refusal, because reading a lost
        // reservation as won leaves no cooldown at all.
        if (is_bool($result)) {
            return $result;
        }

        if ($result === null) {
            return false;
        }

        return strtoupper((string) $result) === 'OK';
    }

    public function delete(string $key): void
    {
        $this->connection->command('del', [$key]);
    }

    public function getDelete(string $key): ?string
    {
        $value = $this->hasGetDel
            ? $this->connection->command('getdel', [$key])
            : $this->connection->eval(PhpRedisCommands::TAKE_SCRIPT, 1, $key);

        return is_string($value) ? $value : null;
    }

    private function detectGetDel(): bool
    {
        try {
            /** @var array<string, mixed>|null $info */
            $info = $this->connection->command('info', ['SERVER']);
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
