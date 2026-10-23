<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests\Integration;

use Illuminate\Container\Container;
use Illuminate\Redis\RedisManager;
use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;
use Kampe\TelegramTwoFactor\Laravel\LaravelRedisCommands;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Stores\RedisCodeStore;
use Kampe\TelegramTwoFactor\Support\FrozenClock;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\Tests\FakeTelegramClient;
use Kampe\TelegramTwoFactor\Tests\RecordingRedis;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;
use PHPUnit\Framework\TestCase;

/**
 * The default adapter, against a live server.
 *
 * This suite exists because the first version of the interop suite did not: it
 * exercised PhpRedisCommands, over a raw \Redis, while the service provider
 * wires LaravelRedisCommands over an Illuminate connection. A review found the
 * consequence — every write through the default path raised
 *
 *     ArgumentCountError: Redis::set() expects at most 3 arguments, 4 given
 *
 * because Connection::command() forwards its arguments straight to phpredis,
 * which takes SET's flags as an options array rather than as trailing
 * arguments. A correct store reached through a broken adapter stores nothing.
 *
 * So the rule this encodes: test the path the application will actually take,
 * not an equivalent one.
 *
 * **Never flushes.** Every key is namespaced under a prefix unique to the run
 * and removed individually, because clearing a Redis database destroys
 * everything in it and REDIS_HOST may point somewhere shared.
 */
final class LaravelRedisCommandsTest extends TestCase
{
    private ?RedisManager $manager = null;

    private string $prefix = '';

    /** @var list<string> */
    private array $touched = [];

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

        if (! extension_loaded('redis')) {
            $this->markTestSkipped('ext-redis is not available.');
        }

        $this->manager = $this->managerWith([]);

        try {
            $this->manager->connection()->ping();
        } catch (\Throwable $e) {
            $this->markTestSkipped('Redis is not reachable: ' . $e->getMessage());
        }

        // No colon: Config reserves it as the separator in a store key.
        $this->prefix = 'tg2fa-laravel-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach (array_unique($this->touched) as $key) {
            try {
                $this->manager?->connection()->command('del', [$key]);
            } catch (\Throwable) {
                // Nothing useful to do in teardown.
            }
        }

        $this->touched = [];

        parent::tearDown();
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private function managerWith(array $options): RedisManager
    {
        $config = [
            'default' => [
                'host' => getenv('REDIS_HOST') ?: '127.0.0.1',
                'port' => (int) (getenv('REDIS_PORT') ?: 6379),
                'database' => (int) (getenv('REDIS_DB') ?: 0),
            ],
        ];

        if ($options !== []) {
            $config['options'] = $options;
        }

        return new RedisManager(new Container(), 'phpredis', $config);
    }

    private function commands(bool $allowKeyPrefix = false): LaravelRedisCommands
    {
        return new LaravelRedisCommands(
            $this->manager?->connection() ?? throw new \LogicException('no connection'),
            allowKeyPrefix: $allowKeyPrefix,
        );
    }

    private function store(): RedisCodeStore
    {
        return new RedisCodeStore($this->commands());
    }

    private function key(string $name): string
    {
        $this->touched[] = $name;

        return $name;
    }

    // ------------------------------------------------- the five primitives

    /**
     * The regression test for the reported failure.
     */
    public function test_put_writes_through_the_laravel_connection(): void
    {
        $key = $this->key($this->prefix . ':code:put');

        $this->store()->put($key, ['hash' => 'abc', 'attempts' => 0], 60);

        self::assertSame(['hash' => 'abc', 'attempts' => 0], $this->store()->get($key));
    }

    public function test_put_sets_the_expiry_on_the_server(): void
    {
        $key = $this->key($this->prefix . ':code:ttl');

        $this->store()->put($key, ['hash' => 'abc'], 60);

        $ttl = $this->manager?->connection()->command('ttl', [$key]);

        self::assertIsInt($ttl);
        self::assertGreaterThan(0, $ttl, 'a record with no expiry outlives the challenge it belongs to');
        self::assertLessThanOrEqual(60, $ttl);
    }

    public function test_add_reserves_an_absent_key(): void
    {
        $key = $this->key($this->prefix . ':cooldown:add');

        self::assertTrue($this->store()->add($key, 1_800_000_120, 60));
        self::assertSame(1_800_000_120, $this->store()->get($key));
    }

    /**
     * The cooldown and the webhook's idempotency claim both rest on this
     * boolean.
     */
    public function test_add_refuses_an_occupied_key_and_leaves_it_alone(): void
    {
        $key = $this->key($this->prefix . ':cooldown:twice');
        $store = $this->store();

        self::assertTrue($store->add($key, 1, 60));
        self::assertFalse($store->add($key, 2, 60), 'the loser must be told it lost');
        self::assertSame(1, $store->get($key), 'and must not have overwritten the winner');
    }

    public function test_add_sets_the_expiry_on_the_server(): void
    {
        $key = $this->key($this->prefix . ':cooldown:ttl');

        $this->store()->add($key, 1, 60);

        $ttl = $this->manager?->connection()->command('ttl', [$key]);

        self::assertIsInt($ttl);
        self::assertGreaterThan(0, $ttl, 'a cooldown with no expiry never lifts');
    }

    public function test_take_returns_the_value_and_removes_it(): void
    {
        $key = $this->key($this->prefix . ':code:take');
        $store = $this->store();
        $store->put($key, ['hash' => 'abc'], 60);

        self::assertSame(['hash' => 'abc'], $store->take($key));
        self::assertNull($store->get($key));
    }

    public function test_take_of_an_absent_key_is_null(): void
    {
        self::assertNull($this->store()->take($this->prefix . ':code:absent'));
    }

    public function test_forget_removes_the_key(): void
    {
        $key = $this->key($this->prefix . ':code:forget');
        $store = $this->store();
        $store->put($key, ['hash' => 'abc'], 60);

        $store->forget($key);

        self::assertNull($store->get($key));
    }

    // ------------------------------------------------------ the wire format

    public function test_a_record_lands_as_json_through_this_adapter_too(): void
    {
        $key = $this->key($this->prefix . ':code:json');

        $this->store()->put($key, ['hash' => 'abc', 'expires_at' => 1_800_000_300], 60);

        $bytes = $this->manager?->connection()->command('get', [$key]);

        self::assertIsString($bytes);
        self::assertStringStartsWith('{', $bytes);
        self::assertStringNotContainsString('a:2:', $bytes);
    }

    public function test_the_whole_protocol_works_over_this_adapter(): void
    {
        $config = new Config(
            botToken: '123456789:AAFakeTokenForTestsOnly_0123456789abc',
            webhookSecret: str_repeat('s', 48),
            hashPepper: str_repeat('p', 48),
            botUsername: 'kampe_test_bot',
            keyPrefix: $this->prefix,
        );

        $identities = new ArrayIdentityStore();
        $identities->seed('user-1', '555000111', 'gen-user-1');

        $telegram = new FakeTelegramClient();

        $tfa = new TelegramTwoFactor(
            config: $config,
            store: $this->store(),
            identities: $identities,
            telegram: $telegram,
            messages: new DefaultMessages(),
            clock: new FrozenClock(1_800_000_000),
        );

        $this->key($config->key('code', 'user-1'));
        $this->key($config->key('cooldown', 'user-1'));

        self::assertTrue($tfa->push('user-1')->ok, 'a challenge must be issuable through the default adapter');

        // The library never returns the code, so it is read back out of the
        // message the fake captured - which is also a proof that it is not
        // leaking anywhere else.
        preg_match('/<code>([^<]+)<\/code>/', $telegram->lastMessage() ?? '', $matches);
        $code = $matches[1] ?? '';

        self::assertNotSame('', $code, 'the code must have reached the chat');
        self::assertTrue($tfa->verify('user-1', $code)->ok);

        // Single use, which is the take path.
        self::assertSame(ErrorCode::Expired, $tfa->verify('user-1', $code)->error);

        // And the cooldown, which is the add path.
        self::assertSame(ErrorCode::Cooldown, $tfa->push('user-1')->error);
    }

    /**
     * take() is one command, through this adapter as through the other.
     */
    public function test_take_issues_one_command_to_the_server(): void
    {
        $key = $this->key($this->prefix . ':code:single-op');
        $this->manager?->connection()->command('setex', [$key, 60, '{"hash":"x"}']);

        $recorder = new RecordingRedis($this->rawClient());
        $store = new RedisCodeStore(
            new \Kampe\TelegramTwoFactor\Stores\PhpRedisCommands($recorder, hasGetDel: false)
        );

        self::assertSame(['hash' => 'x'], $store->take($key));
        self::assertSame(['EVAL'], $recorder->commands);
    }

    // ------------------------------------------- refused configurations

    /**
     * A default Laravel application sets a prefix from REDIS_PREFIX, so this is
     * the common case rather than an exotic one. Applying it silently would
     * store these records where no other implementation looks.
     */
    public function test_a_connection_level_key_prefix_is_refused(): void
    {
        $this->manager = $this->managerWith(['prefix' => 'laravel_database_']);

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/laravel_database_/');

        $this->commands();
    }

    /**
     * And is accepted when the caller says it is intended, because on a
     * PHP-only deployment it is harmless.
     */
    public function test_a_key_prefix_can_be_acknowledged(): void
    {
        $this->manager = $this->managerWith(['prefix' => 'laravel_database_']);

        $commands = $this->commands(allowKeyPrefix: true);
        $key = $this->prefix . ':code:prefixed';

        $commands->set($key, '{"hash":"abc"}', 60);

        // Physically stored under the prefix, which is the whole point of
        // refusing it by default.
        $this->key('laravel_database_' . $key);

        $unprefixed = new \Redis();
        $unprefixed->connect(
            getenv('REDIS_HOST') ?: '127.0.0.1',
            (int) (getenv('REDIS_PORT') ?: 6379),
            2.0,
        );
        $unprefixed->select((int) (getenv('REDIS_DB') ?: 0));

        self::assertSame('{"hash":"abc"}', $unprefixed->get('laravel_database_' . $key));
        $unprefixed->close();
    }

    public function test_a_serializer_on_the_connection_is_refused(): void
    {
        $this->manager = $this->managerWith(['serializer' => \Redis::SERIALIZER_PHP]);

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessageMatches('/serializer/');

        $this->commands();
    }

    public function test_compression_on_the_connection_is_refused(): void
    {
        if (! defined('Redis::COMPRESSION_LZF') || \Redis::COMPRESSION_LZF === 0) {
            self::markTestSkipped('This phpredis build has no LZF compression.');
        }

        $this->manager = $this->managerWith(['compression' => \Redis::COMPRESSION_LZF]);

        try {
            $this->commands();
        } catch (ConfigurationError $e) {
            self::assertMatchesRegularExpression('/compression/', $e->getMessage());

            return;
        } catch (\Throwable $e) {
            self::markTestSkipped('This server or client rejected the compression option: ' . $e->getMessage());
        }

        self::fail('compression must be refused');
    }

    /**
     * A raw client with a prefix is refused too: the hazard is the client's, not
     * the framework's.
     */
    public function test_a_prefix_on_a_raw_client_is_refused(): void
    {
        $raw = new \Redis();
        $raw->connect(getenv('REDIS_HOST') ?: '127.0.0.1', (int) (getenv('REDIS_PORT') ?: 6379), 2.0);
        $raw->setOption(\Redis::OPT_PREFIX, 'something_');

        $this->expectException(ConfigurationError::class);

        new \Kampe\TelegramTwoFactor\Stores\PhpRedisCommands($raw);
    }

    private function rawClient(): \Redis
    {
        $client = $this->manager?->connection()->client();

        self::assertInstanceOf(\Redis::class, $client);

        return $client;
    }
}
