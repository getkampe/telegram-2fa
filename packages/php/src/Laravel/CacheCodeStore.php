<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Contracts\Cache\Repository;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;

/**
 * Backs the code store with Laravel's cache.
 *
 * Pick a driver that is shared across processes and survives a deploy: redis,
 * memcached or database. The array driver is per-process, and file is per-server,
 * so on either one a code issued by one request can be invisible to the next.
 */
final class CacheCodeStore implements CodeStore
{
    public function __construct(private readonly Repository $cache)
    {
    }

    public function get(string $key): mixed
    {
        return $this->cache->get($key);
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->cache->put($key, $value, $ttlSeconds);
    }

    public function forget(string $key): void
    {
        $this->cache->forget($key);
    }

    /**
     * Laravel's pull() is get-then-forget at the repository level, so it is only
     * truly atomic on a driver whose own primitive is. On redis and memcached it
     * is; on database, file and array it is not, and two simultaneous
     * verifications of one code can both win.
     *
     * That is the main reason this package tells you to use redis or memcached
     * rather than treating the choice as a performance detail.
     */
    public function take(string $key): mixed
    {
        return $this->cache->pull($key);
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        // Repository::add is atomic on every driver Laravel ships: the ones
        // without a native add are serialised behind a lock.
        return $this->cache->add($key, $value, $ttlSeconds);
    }
}
