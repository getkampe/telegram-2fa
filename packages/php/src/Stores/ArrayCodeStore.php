<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Contracts\Clock;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Support\SystemClock;

/**
 * An in-process store, for tests and for single-process scripts.
 *
 * Not for production on a web server: each PHP worker would get its own copy, so
 * a code issued by one request would be invisible to the next. Use Redis, your
 * framework's cache, or a table with an expires_at column.
 */
final class ArrayCodeStore implements CodeStore
{
    /** @var array<string, array{value: mixed, expires_at: int}> */
    private array $items = [];

    private readonly Clock $clock;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    public function get(string $key): mixed
    {
        $item = $this->items[$key] ?? null;

        if ($item === null) {
            return null;
        }

        if ($item['expires_at'] <= $this->clock->now()) {
            unset($this->items[$key]);

            return null;
        }

        return $item['value'];
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->items[$key] = [
            'value' => $value,
            'expires_at' => $this->clock->now() + $ttlSeconds,
        ];
    }

    public function forget(string $key): void
    {
        unset($this->items[$key]);
    }

    /**
     * Trivially atomic here: one process, one array, no interleaving point
     * between the read and the unset.
     */
    public function take(string $key): mixed
    {
        $value = $this->get($key);

        unset($this->items[$key]);

        return $value;
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        if ($this->get($key) !== null) {
            return false;
        }

        $this->put($key, $value, $ttlSeconds);

        return true;
    }

    /**
     * Test helper: how many live keys the store holds.
     */
    public function count(): int
    {
        $live = 0;

        foreach (array_keys($this->items) as $key) {
            if ($this->get($key) !== null) {
                $live++;
            }
        }

        return $live;
    }
}
