<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests\Integration;

use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;
use Illuminate\Redis\RedisManager;
use Kampe\TelegramTwoFactor\Laravel\CacheCodeStore;
use PHPUnit\Framework\TestCase;

/**
 * The adapter against a live Redis, which is the only thing that can establish
 * the guarantee the package claims in production.
 *
 * The ArrayStore tests prove the adapter consults a lock; they cannot prove
 * that the lock is shared between processes, because an in-process lock trivially
 * is not. Only a real server shows that.
 *
 * Skipped unless REDIS_HOST is set, and run in CI against a Redis service — see
 * .github/workflows/ci.yml. Nothing here is a substitute for the skip: if this
 * suite is skipped, the cross-process claim is untested, and that is stated in
 * SECURITY.md rather than glossed over.
 */
final class RedisCacheCodeStoreTest extends TestCase
{
    private ?Repository $cache = null;

    protected function setUp(): void
    {
        parent::setUp();

        $host = getenv('REDIS_HOST');

        if ($host === false || $host === '') {
            $this->markTestSkipped('REDIS_HOST is not set; skipping live Redis integration.');
        }

        if (! class_exists(RedisManager::class)) {
            $this->markTestSkipped('illuminate/redis is not installed.');
        }

        if (! extension_loaded('redis') && ! class_exists(\Predis\Client::class)) {
            $this->markTestSkipped('Neither phpredis nor predis is available.');
        }

        $manager = new RedisManager(
            new \Illuminate\Container\Container(),
            extension_loaded('redis') ? 'phpredis' : 'predis',
            [
                'default' => [
                    'host' => $host,
                    'port' => (int) (getenv('REDIS_PORT') ?: 6379),
                    'database' => (int) (getenv('REDIS_DB') ?: 15),
                ],
            ],
        );

        $store = new RedisStore($manager, 'tg2fa-test:');
        $this->cache = new Repository($store);
        $this->cache->clear();
    }

    protected function tearDown(): void
    {
        $this->cache?->clear();

        parent::tearDown();
    }

    private function store(): CacheCodeStore
    {
        // No permitLocalStore: a real Redis store must be accepted on its own
        // merits, which is itself part of what this asserts.
        return new CacheCodeStore($this->cache, waitSeconds: 2);
    }

    public function test_it_round_trips_through_redis(): void
    {
        $store = $this->store();

        $store->put('a', ['hash' => 'x', 'attempts' => 0], 60);

        $this->assertSame(['hash' => 'x', 'attempts' => 0], $store->get('a'));

        $store->forget('a');
        $this->assertNull($store->get('a'));
    }

    public function test_take_yields_a_value_once(): void
    {
        $store = $this->store();
        $store->put('a', 'value', 60);

        $this->assertSame('value', $store->take('a'));
        $this->assertNull($store->take('a'));
    }

    public function test_add_reserves_once(): void
    {
        $store = $this->store();

        $this->assertTrue($store->add('a', 1, 60));
        $this->assertFalse($store->add('a', 2, 60));
        $this->assertSame(1, $store->get('a'));
    }

    /**
     * The cross-process property, through two independent store instances over
     * two connections — as close to two workers as one test process gets.
     */
    public function test_a_lock_held_by_one_instance_is_visible_to_another(): void
    {
        $first = $this->store();
        $first->put('a', 'value', 60);

        /** @var RedisStore $redisStore */
        $redisStore = $this->cache->getStore();
        $lock = $redisStore->lock('tg2fa:lock:a', 5);

        $this->assertTrue($lock->acquire());

        try {
            // A second adapter instance, waiting only briefly, must decline
            // rather than read through a lock another holder owns.
            $second = new CacheCodeStore($this->cache, waitSeconds: 0);

            $this->assertNull(
                $second->take('a'),
                'the lock must be visible across instances, not just within one'
            );
        } finally {
            $lock->release();
        }

        $this->assertSame('value', $first->take('a'), 'and the value survives the declined take');
    }

    public function test_expiry_is_enforced_by_the_server(): void
    {
        $store = $this->store();

        // One second is the smallest TTL Redis accepts for EX.
        $store->put('a', 'value', 1);
        $this->assertSame('value', $store->get('a'));

        // Deliberately a real wait: the point is that Redis expires it, which
        // no injected clock can demonstrate.
        sleep(2);

        $this->assertNull($store->get('a'));
    }
}
