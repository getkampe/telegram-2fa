<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests\Integration;

use Illuminate\Cache\RedisStore;
use Illuminate\Cache\Repository;
use Illuminate\Container\Container;
use Illuminate\Redis\RedisManager;
use Kampe\TelegramTwoFactor\Laravel\CacheCodeStore;
use PHPUnit\Framework\TestCase;
use Predis\Client as PredisClient;

/**
 * The adapter against a live Redis, which is the only thing that can establish
 * the guarantee the package claims in production.
 *
 * The ArrayStore tests prove the adapter consults a lock; they cannot prove the
 * lock is shared between processes, because an in-process lock trivially is
 * not. Only a real server shows that.
 *
 * Skipped unless REDIS_HOST is set, and run in CI against a Redis service — see
 * .github/workflows/ci.yml, which fails the build if this suite skips. If it
 * does skip, the cross-process claim is untested, and SECURITY.md says so
 * rather than glossing over it.
 *
 * **This suite never flushes.** It would be natural to call Cache::clear()
 * between tests, and on a Redis store that is FLUSHDB — it destroys the whole
 * database, not merely the keys this test wrote. That is harmless against a
 * disposable CI container and emphatically not harmless when REDIS_HOST points
 * at a developer's machine or anything shared. So every key is namespaced under
 * a prefix unique to the run and removed individually.
 */
final class RedisCacheCodeStoreTest extends TestCase
{
    private ?Repository $cache = null;

    /** @var list<string> */
    private array $touched = [];

    private string $prefix = '';

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

        $driver = extension_loaded('redis')
            ? 'phpredis'
            : (class_exists(PredisClient::class) ? 'predis' : null);

        if ($driver === null) {
            $this->markTestSkipped('Neither phpredis nor predis is available.');
        }

        // Unique per run, so concurrent runs cannot collide and nothing outside
        // this prefix is ever addressed.
        $this->prefix = 'tg2fa-test:' . bin2hex(random_bytes(6)) . ':';

        $manager = new RedisManager(new Container(), $driver, [
            'default' => [
                'host' => $host,
                'port' => (int) (getenv('REDIS_PORT') ?: 6379),
                'database' => (int) (getenv('REDIS_DB') ?: 0),
            ],
        ]);

        try {
            $manager->connection()->ping();
        } catch (\Throwable $e) {
            $this->markTestSkipped('Redis is not reachable: ' . $e->getMessage());
        }

        $this->cache = new Repository(new RedisStore($manager, $this->prefix));
    }

    protected function tearDown(): void
    {
        // Only our own keys. No flush: see the class comment.
        foreach (array_unique($this->touched) as $key) {
            $this->cache?->forget($key);
        }

        $this->touched = [];

        parent::tearDown();
    }

    private function store(int $waitSeconds = 2): CacheCodeStore
    {
        // No permitLocalStore: a real Redis store must be accepted on its own
        // merits, which is itself part of what this asserts.
        return new CacheCodeStore($this->cache, waitSeconds: $waitSeconds);
    }

    private function key(string $name): string
    {
        $this->touched[] = $name;

        return $name;
    }

    public function test_it_round_trips_through_redis(): void
    {
        $store = $this->store();
        $key = $this->key('code:user-1');

        $store->put($key, ['hash' => 'x', 'attempts' => 0], 60);

        $this->assertSame(['hash' => 'x', 'attempts' => 0], $store->get($key));

        $store->forget($key);
        $this->assertNull($store->get($key));
    }

    public function test_take_yields_a_value_once(): void
    {
        $store = $this->store();
        $key = $this->key('code:take-once');
        $store->put($key, 'value', 60);

        $this->assertSame('value', $store->take($key));
        $this->assertNull($store->take($key), 'a taken value must not come back');
    }

    public function test_add_reserves_once(): void
    {
        $store = $this->store();
        $key = $this->key('cooldown:user-1');

        $this->assertTrue($store->add($key, 1, 60));
        $this->assertFalse($store->add($key, 2, 60), 'a second reservation must lose');

        // Loosely compared on purpose. Laravel's Redis store leaves a bare
        // numeric unserialised so that INCR still works on it, so an int goes
        // in and a numeric string comes back. The array records are unaffected
        // — those are PHP-serialised and keep their types — but the cooldown is
        // a bare integer, which is why the library coerces when it reads one
        // and why a port that compares with === would break here and nowhere
        // else.
        $this->assertEquals(1, $store->get($key), 'and must not overwrite the winner');
        $this->assertSame('1', (string) $store->get($key));
    }

    /**
     * The cross-process property: a lock taken by one holder is visible to a
     * separate adapter instance, which is what an in-process lock cannot show.
     */
    public function test_a_lock_held_by_one_holder_is_visible_to_another(): void
    {
        $first = $this->store();
        $key = $this->key('code:contended');
        $first->put($key, 'value', 60);

        /** @var RedisStore $redisStore */
        $redisStore = $this->cache->getStore();
        $lock = $redisStore->lock('tg2fa:lock:' . $key, 5);

        $this->assertTrue($lock->acquire(), 'the test needs the lock to set the scene');

        try {
            $second = new CacheCodeStore($this->cache, waitSeconds: 0);

            $this->assertNull(
                $second->take($key),
                'the lock must be visible across adapter instances, not only within one'
            );

            // And the primitive the adapter used to be built on ignores it.
            $this->assertSame('value', $this->cache->pull($key), 'pull() ignores the lock');
        } finally {
            $lock->release();
        }
    }

    public function test_the_lock_is_released_after_each_operation(): void
    {
        $store = $this->store();
        $key = $this->key('code:released');

        $store->put($key, 'value', 60);
        $store->take($key);
        $store->add($key, 'again', 60);

        /** @var RedisStore $redisStore */
        $redisStore = $this->cache->getStore();
        $lock = $redisStore->lock('tg2fa:lock:' . $key, 5);

        $this->assertTrue($lock->acquire(), 'locks must not leak between operations');
        $lock->release();
    }

    /**
     * The whole protocol over a real store, which is the only way to know that
     * the adapter is not merely self-consistent.
     *
     * It is also what would have caught the loose typing above from the other
     * side: the cooldown is written as an integer and read back as a string,
     * and every path that touches it has to cope.
     */
    public function test_a_challenge_round_trips_through_the_live_store(): void
    {
        $this->touched[] = 'tg2fa:code:user-live';
        $this->touched[] = 'tg2fa:cooldown:user-live';

        $identities = new \Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore();
        $identities->seed('user-live', '555000111', 'gen-live');
        $telegram = new \Kampe\TelegramTwoFactor\Tests\FakeTelegramClient();

        $tfa = new \Kampe\TelegramTwoFactor\TelegramTwoFactor(
            \Kampe\TelegramTwoFactor\Config::fromArray([
                'bot_token' => '123456789:AAFakeTokenForTestsOnly_0123456789abc',
                'webhook_secret' => str_repeat('s', 48),
                'hash_pepper' => str_repeat('p', 48),
            ]),
            $this->store(),
            $identities,
            $telegram,
            new \Kampe\TelegramTwoFactor\Telegram\DefaultMessages(),
        );

        $this->assertTrue($tfa->push('user-live', 'withdrawal')->ok);

        preg_match('/<code>([^<]+)<\/code>/', $telegram->lastMessage() ?? '', $m);
        $code = $m[1] ?? '';
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);

        // The cooldown must be observed through the real store, which means the
        // numeric string it returns has to be understood as a timestamp.
        $second = $tfa->push('user-live', 'withdrawal');
        $this->assertFalse($second->ok);
        $this->assertSame(
            \Kampe\TelegramTwoFactor\ErrorCode::Cooldown,
            $second->error,
            'a cooldown read back as a string must still block a second send'
        );
        $this->assertGreaterThan(time(), (int) $second->nextSendAt);

        $this->assertTrue($tfa->verify('user-live', $code, 'withdrawal')->ok);

        // Single use, over the wire.
        $this->assertFalse($tfa->verify('user-live', $code, 'withdrawal')->ok);
    }

    public function test_expiry_is_enforced_by_the_server(): void
    {
        $store = $this->store();
        $key = $this->key('code:expiring');

        // One second is the smallest TTL Redis accepts for EX.
        $store->put($key, 'value', 1);
        $this->assertSame('value', $store->get($key));

        // Deliberately a real wait: that Redis itself expires the record is
        // precisely what no injected clock can demonstrate.
        sleep(2);

        $this->assertNull($store->get($key), 'the server must expire the record on its own');
    }
}
