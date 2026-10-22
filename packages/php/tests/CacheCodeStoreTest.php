<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\FileStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Filesystem\Filesystem;
use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;
use Kampe\TelegramTwoFactor\Laravel\CacheCodeStore;
use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * The production adapter, against real Illuminate cache stores rather than a
 * stand-in.
 *
 * The bug this covers is one an in-memory test could never find: the adapter
 * used Repository::pull() and a comment claimed Redis made it atomic. pull() is
 *
 *     tap($this->get($key), fn () => $this->forget($key));
 *
 * on every driver, so it never was. These tests assert against the real
 * Repository, and the contention cases assert the lock is genuinely consulted —
 * which is the only observable difference between the two implementations in a
 * single process.
 */
final class CacheCodeStoreTest extends BaseTestCase
{
    private function repository(): Repository
    {
        return new Repository(new ArrayStore());
    }

    /**
     * @param  int  $waitSeconds  Zero in the contention tests: the point there
     *                            is that the lock is consulted, not how
     *                            patiently the adapter waits, and a full retry
     *                            budget would add seconds per case.
     */
    private function store(Repository $cache, int $waitSeconds = 1): CacheCodeStore
    {
        // ArrayStore is local, so the adapter refuses it unless told this is a
        // test. That refusal is itself asserted below.
        return new CacheCodeStore($cache, waitSeconds: $waitSeconds, permitLocalStore: true);
    }

    public function test_it_round_trips_values(): void
    {
        $store = $this->store($this->repository());

        $this->assertNull($store->get('a'));

        $store->put('a', ['hash' => 'x'], 60);
        $this->assertSame(['hash' => 'x'], $store->get('a'));

        $store->forget('a');
        $this->assertNull($store->get('a'));
    }

    public function test_take_returns_the_value_once(): void
    {
        $store = $this->store($this->repository());
        $store->put('a', 'value', 60);

        $this->assertSame('value', $store->take('a'));
        $this->assertNull($store->take('a'), 'a taken value must not come back');
    }

    public function test_add_reserves_once(): void
    {
        $store = $this->store($this->repository());

        $this->assertTrue($store->add('a', 1, 60));
        $this->assertFalse($store->add('a', 2, 60), 'a second reservation must lose');
        $this->assertSame(1, $store->get('a'), 'and must not overwrite the winner');
    }

    /**
     * The real assertion about atomicity available in one process: with the
     * key's lock held elsewhere, take() must decline rather than read through.
     *
     * Repository::pull() would happily return the value here, which is exactly
     * the race the adapter used to have.
     */
    public function test_take_declines_while_another_holder_has_the_key(): void
    {
        $cache = $this->repository();
        $store = $this->store($cache, waitSeconds: 0);
        $store->put('a', 'value', 60);

        /** @var ArrayStore $arrayStore */
        $arrayStore = $cache->getStore();
        $lock = $arrayStore->lock('tg2fa:lock:a', 5);

        $this->assertTrue($lock->acquire(), 'the test needs the lock to set the scene');

        try {
            $this->assertNull(
                $store->take('a'),
                'take() must not read through a held lock — that is the race it exists to avoid'
            );

            // Demonstrate the difference: the primitive the adapter used to be
            // built on ignores the lock entirely.
            $this->assertSame('value', $cache->pull('a'), 'pull() ignores the lock');
        } finally {
            $lock->release();
        }
    }

    public function test_add_declines_while_another_holder_has_the_key(): void
    {
        $cache = $this->repository();
        $store = $this->store($cache, waitSeconds: 0);

        /** @var ArrayStore $arrayStore */
        $arrayStore = $cache->getStore();
        $lock = $arrayStore->lock('tg2fa:lock:cooldown', 5);
        $this->assertTrue($lock->acquire());

        try {
            $this->assertFalse(
                $store->add('cooldown', 123, 60),
                'a reservation that cannot take the lock has lost the reservation'
            );
        } finally {
            $lock->release();
        }
    }

    public function test_the_lock_is_released_after_each_operation(): void
    {
        $cache = $this->repository();
        $store = $this->store($cache);

        $store->put('a', 'value', 60);
        $store->take('a');
        $store->add('a', 'again', 60);

        // If any operation leaked its lock, this acquire would fail and the
        // next request touching the key would silently get null.
        /** @var ArrayStore $arrayStore */
        $arrayStore = $cache->getStore();
        $lock = $arrayStore->lock('tg2fa:lock:a', 5);

        $this->assertTrue($lock->acquire(), 'locks must not leak between operations');
        $lock->release();
    }

    public function test_a_store_without_a_lock_is_refused(): void
    {
        $storeWithoutLocks = new class implements Store {
            public function get($key)
            {
                return null;
            }

            public function many(array $keys)
            {
                return [];
            }

            public function put($key, $value, $seconds)
            {
                return true;
            }

            public function putMany(array $values, $seconds)
            {
                return true;
            }

            public function increment($key, $value = 1)
            {
                return 1;
            }

            public function decrement($key, $value = 1)
            {
                return 1;
            }

            public function forever($key, $value)
            {
                return true;
            }

            public function forget($key)
            {
                return true;
            }

            public function flush()
            {
                return true;
            }

            public function getPrefix()
            {
                return '';
            }
        };

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/no atomic lock/');

        new CacheCodeStore(new Repository($storeWithoutLocks));
    }

    public function test_the_array_store_is_refused_by_default(): void
    {
        // It has locks, but they are in-process: a second PHP worker shares
        // neither the data nor the lock.
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/not shared across the processes/');

        new CacheCodeStore($this->repository());
    }

    public function test_the_file_store_is_refused_by_default(): void
    {
        $file = new FileStore(new Filesystem(), sys_get_temp_dir() . '/tg2fa-test-cache');

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/not shared across the processes/');

        new CacheCodeStore(new Repository($file));
    }
}
