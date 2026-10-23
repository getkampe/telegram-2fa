<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Cache\Store;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;
use Kampe\TelegramTwoFactor\Exceptions\StoreContention;

/**
 * Backs the code store with Laravel's cache.
 *
 * **PHP-only.** Prefer RedisCodeStore, which is what the service provider now
 * wires by default. This class is correct for a deployment where every process
 * that touches these keys is PHP, and it is wrong for any other, in two ways
 * that a single-language test suite cannot see:
 *
 * - **Encoding.** Laravel's Redis cache runs values through serialize(), so a
 *   record lands as `a:6:{s:4:"hash";...}`. Every other implementation of this
 *   protocol reads and writes the JSON of SPEC.md section 9, so its records are
 *   unreadable to them and theirs to it. The shared fixtures in /conformance did
 *   not catch this: they check the shape of a record against an in-memory store,
 *   not the bytes the production adapter puts on the wire.
 * - **Atomicity.** The take below is serialised behind the store's own named
 *   lock. That holds between PHP processes and means nothing to a Node or Go
 *   process, which issues GETDEL and never takes the lock — so the two can
 *   interleave and one code can be accepted twice.
 *
 * Neither is a reason to delete it: on a Laravel-only deployment the lock is a
 * real guarantee across workers and machines, and the cache abstraction lets it
 * run on Memcached or DynamoDB as well as Redis. But reach for it deliberately,
 * by setting telegram-2fa.code_store to 'cache', rather than by default.
 *
 * The interesting part of this class is what it does *not* use.
 * Repository::pull() looks like an atomic take, and is not: it is
 *
 *     tap($this->get($key), fn () => $this->forget($key));
 *
 * on every driver. Redis underneath does not make those two calls one
 * operation, so a verification built on pull() races exactly as a hand-written
 * get-then-forget would, and two simultaneous verifications of one code can
 * both succeed. An earlier version of this class used pull() and claimed
 * otherwise in a comment.
 *
 * Instead, every mutation is serialised behind the store's own named lock, so
 * mutations of a given key cannot interleave. get() is left unlocked on purpose:
 * a stale read is harmless, because every path that accepts a code re-validates
 * it against the enrollment generation before acting.
 *
 * The guarantee is therefore exactly as strong as the lock driver. Redis,
 * Memcached, DynamoDB and the database driver provide cross-process locks;
 * ArrayStore's lock is in-process only and FileStore's is per-server, which is
 * why both are refused unless explicitly permitted.
 */
final class CacheCodeStore implements CodeStore
{
    private const RETRY_MICROSECONDS = 20_000;

    private readonly LockProvider $locks;

    /**
     * @param  int  $lockSeconds   How long a held lock survives a dead process.
     * @param  int  $waitSeconds   How long to wait for a contended lock.
     * @param  bool $permitLocalStore  Allow array/file stores. For tests and
     *                                 single-process scripts only.
     */
    public function __construct(
        private readonly Repository $cache,
        private readonly int $lockSeconds = 5,
        private readonly int $waitSeconds = 3,
        bool $permitLocalStore = false,
    ) {
        $store = $this->cache->getStore();

        if (! $store instanceof LockProvider) {
            throw new ConfigurationError(sprintf(
                'The cache store %s provides no atomic lock, so this package cannot guarantee '
                . 'that a code is used once. Use the redis or memcached cache store. '
                . 'Refusing to start is deliberate: the alternative is appearing to work while '
                . 'two simultaneous verifications of one code both succeed.',
                $store::class,
            ));
        }

        if (! $permitLocalStore && $this->isLocalOnly($store)) {
            throw new ConfigurationError(sprintf(
                'The cache store %s is not shared across the processes that will serve your '
                . 'requests: its locks and its data are local, so a code issued by one worker '
                . 'can be invisible to the next and two workers can verify the same code. '
                . 'Use redis or memcached. Pass $permitLocalStore to override this in tests.',
                $store::class,
            ));
        }

        $this->locks = $store;
    }

    /**
     * Unlocked by design. Callers treat a read as advisory; nothing is
     * authorised on the strength of one.
     */
    public function get(string $key): mixed
    {
        return $this->cache->get($key);
    }

    /**
     * Locked, because an unlocked write could land inside another caller's
     * take() — between its read and its delete — and be destroyed by it.
     *
     * Contention throws rather than returning quietly: a dropped write here
     * means a challenge the application believes it issued and the user never
     * receives.
     */
    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $this->mustLock($key, fn () => $this->cache->put($key, $value, $ttlSeconds));
    }

    public function forget(string $key): void
    {
        $this->mustLock($key, fn () => $this->cache->forget($key));
    }

    public function take(string $key): mixed
    {
        // Losing the lock is not an error here, and null is the semantically
        // exact answer: another caller is inside this key's critical section,
        // so it holds the only copy of whatever was there.
        return $this->withLock($key, function () use ($key) {
            $value = $this->cache->get($key);

            if ($value !== null) {
                $this->cache->forget($key);
            }

            return $value;
        }, null);
    }

    public function add(string $key, mixed $value, int $ttlSeconds): bool
    {
        // Repository::add delegates to a native store add where one exists —
        // Redis does it in a Lua script, Memcached has a native ADD — so this
        // is already a single operation on the drivers that matter. The lock
        // covers the drivers where it falls back to get-then-put, and keeps
        // reservations from interleaving with put() and take() on the same key.
        //
        // Losing the lock means another caller is reserving: that is a lost
        // reservation, which is exactly what false reports.
        return (bool) $this->withLock(
            $key,
            fn () => $this->cache->add($key, $value, $ttlSeconds),
            false,
        );
    }

    /**
     * Run $operation holding this key's lock, or return $onContention.
     *
     * @template T
     *
     * @param  callable(): T  $operation
     * @param  T  $onContention
     * @return T
     */
    private function withLock(string $key, callable $operation, mixed $onContention): mixed
    {
        $lock = $this->locks->lock($this->lockKey($key), $this->lockSeconds);

        if (! $this->acquire($lock)) {
            return $onContention;
        }

        try {
            return $operation();
        } finally {
            $lock->release();
        }
    }

    /**
     * As withLock, but contention is an error rather than an answer.
     *
     * @param  callable(): mixed  $operation
     */
    private function mustLock(string $key, callable $operation): void
    {
        $lock = $this->locks->lock($this->lockKey($key), $this->lockSeconds);

        if (! $this->acquire($lock)) {
            throw new StoreContention(sprintf(
                'Could not take the lock for a cache write after %d attempts. Either the store '
                . 'is extraordinarily contended, or its lock driver is not releasing locks.',
                $this->attempts(),
            ));
        }

        try {
            $operation();
        } finally {
            $lock->release();
        }
    }

    /**
     * Bounded retry. Deliberately not Lock::block(), which calls Laravel's
     * global now() helper — a library should not require the framework's
     * helpers file to have been loaded.
     */
    private function acquire(Lock $lock): bool
    {
        $attempts = $this->attempts();

        for ($i = 0; $i < $attempts; $i++) {
            if ($lock->acquire()) {
                return true;
            }

            if ($i < $attempts - 1) {
                usleep(self::RETRY_MICROSECONDS);
            }
        }

        return false;
    }

    private function attempts(): int
    {
        return max(1, (int) ($this->waitSeconds * 1_000_000 / self::RETRY_MICROSECONDS));
    }

    private function lockKey(string $key): string
    {
        return 'tg2fa:lock:' . $key;
    }

    private function isLocalOnly(Store $store): bool
    {
        return $store instanceof ArrayStore || $store instanceof FileStore;
    }
}
