<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

/**
 * Wraps a \Redis and records the commands actually sent to the server.
 *
 * The layer matters. A recorder placed around RedisCommands sees one
 * getDelete() call whether that method issues GETDEL or a client-side GET
 * followed by a DEL, because the split is inside it — so such a test passes
 * against the very bug it is supposed to catch. This sits underneath, where the
 * commands are.
 *
 * Methods are declared rather than handled by __call, because PhpRedisCommands
 * checks for them with method_exists().
 */
final class RecordingRedis
{
    /** @var list<string> */
    public array $commands = [];

    public function __construct(private readonly \Redis $redis) {}

    public function reset(): void
    {
        $this->commands = [];
    }

    public function get(string $key): mixed
    {
        $this->commands[] = 'GET';

        return $this->redis->get($key);
    }

    /**
     * @param  array<array-key, mixed>|int|null  $options
     */
    public function set(string $key, mixed $value, mixed $options = null): mixed
    {
        $this->commands[] = is_array($options) && in_array('NX', $options, true) ? 'SET NX' : 'SET';

        return $options === null
            ? $this->redis->set($key, $value)
            : $this->redis->set($key, $value, $options);
    }

    public function del(mixed ...$keys): mixed
    {
        $this->commands[] = 'DEL';

        return $this->redis->del(...$keys);
    }

    public function getDel(string $key): mixed
    {
        $this->commands[] = 'GETDEL';

        return $this->redis->getDel($key);
    }

    /**
     * @param  array<array-key, mixed>  $arguments
     */
    public function eval(string $script, array $arguments = [], int $numKeys = 0): mixed
    {
        $this->commands[] = 'EVAL';

        return $this->redis->eval($script, $arguments, $numKeys);
    }

    public function info(string ...$sections): mixed
    {
        $this->commands[] = 'INFO';

        return $this->redis->info(...$sections);
    }
}
