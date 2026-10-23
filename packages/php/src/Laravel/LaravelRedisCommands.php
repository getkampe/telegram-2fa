<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Contracts\Redis\Connection;
use Kampe\TelegramTwoFactor\Contracts\RedisCommands;
use Kampe\TelegramTwoFactor\Stores\PhpRedisCommands;
use Kampe\TelegramTwoFactor\Stores\RedisClientOptions;

/**
 * RedisCommands over an Illuminate Redis connection.
 *
 * Deliberately the connection and not the cache repository. The cache repository
 * serialises values with PHP's serialize(), which is what makes records written
 * through Laravel's cache unreadable to every other implementation of this
 * protocol — see the class comment on RedisCodeStore.
 *
 * That is the only thing using the connection fixes. The connection carries its
 * own options, set straight from config, and two of them would break interop
 * just as thoroughly: a serializer or compression setting changes the bytes, and
 * `options.prefix` changes the keys. A default Laravel application sets a prefix
 * from REDIS_PREFIX, so this is the common case and not an exotic one. The
 * constructor checks for all three rather than letting them apply quietly — see
 * RedisClientOptions.
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
     * @param  bool  $allowKeyPrefix  Acknowledge a connection-level key prefix,
     *                                for a PHP-only deployment or one where
     *                                every client applies the same prefix.
     */
    public function __construct(
        private readonly Connection $connection,
        ?bool $hasGetDel = null,
        bool $allowKeyPrefix = false,
    ) {
        $client = method_exists($this->connection, 'client') ? $this->connection->client() : null;

        if (is_object($client)) {
            RedisClientOptions::assertInteroperable($client, $allowKeyPrefix);
            RedisClientOptions::assertNoPredisPrefix($client, $allowKeyPrefix);
        }

        $this->hasGetDel = $hasGetDel ?? $this->detectGetDel();
    }

    public function get(string $key): ?string
    {
        $value = $this->connection->command('get', [$key]);

        return is_string($value) ? $value : null;
    }

    /**
     * SET with an expiry, and optionally NX.
     *
     * Through the connection's own set() method, not command('set', ...).
     * command() forwards its arguments straight to the underlying client, and
     * phpredis takes its flags as an options array rather than as trailing
     * arguments — so command('set', [$key, $value, 'EX', $ttl]) raises
     * "Redis::set() expects at most 3 arguments, 4 given" and nothing is ever
     * written. The normalisation that turns ('EX', $ttl, 'NX') into phpredis's
     * ['NX', 'EX' => $ttl] lives on the concrete connection classes, which is
     * also why this calls a method the Connection interface does not declare.
     * Predis takes the trailing form directly, and its connection passes these
     * arguments through unchanged, so one call serves both.
     */
    public function set(string $key, string $value, int $ttlSeconds, bool $onlyIfAbsent = false): bool
    {
        /** @var mixed $result */
        $result = $onlyIfAbsent
            ? $this->connection->set($key, $value, 'EX', $ttlSeconds, 'NX')
            : $this->connection->set($key, $value, 'EX', $ttlSeconds);

        return $this->stored($result);
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

    /**
     * Whether a SET reply means the value was stored.
     *
     * phpredis answers true or false; predis answers a Status object whose
     * payload is OK, or null when NX declines. Anything that is not an
     * affirmative is a refusal, because reading a lost reservation as won leaves
     * no cooldown at all and makes the webhook process an update twice.
     */
    private function stored(mixed $result): bool
    {
        if (is_bool($result)) {
            return $result;
        }

        if ($result === null) {
            return false;
        }

        if (is_object($result) && method_exists($result, 'getPayload')) {
            return strtoupper((string) $result->getPayload()) === 'OK';
        }

        return is_scalar($result) && strtoupper((string) $result) === 'OK';
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
