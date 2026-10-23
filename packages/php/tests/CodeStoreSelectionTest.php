<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Illuminate\Container\Container;
use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;
use Kampe\TelegramTwoFactor\Laravel\CacheCodeStore;
use Kampe\TelegramTwoFactor\Laravel\TelegramTwoFactorServiceProvider;
use Kampe\TelegramTwoFactor\Stores\RedisCodeStore;
use PHPUnit\Framework\TestCase;

/**
 * Which store the service provider wires.
 *
 * This is the delivery mechanism for the whole fix: a correct adapter that
 * nothing resolves by default changes nothing in production. The default must be
 * the cross-language one, and choosing the PHP-only one must be something an
 * application says out loud.
 */
final class CodeStoreSelectionTest extends TestCase
{
    public function test_the_default_is_the_cross_language_redis_store(): void
    {
        self::assertInstanceOf(RedisCodeStore::class, $this->resolve([]));
    }

    public function test_redis_can_be_chosen_explicitly(): void
    {
        self::assertInstanceOf(RedisCodeStore::class, $this->resolve(['code_store' => 'redis']));
    }

    /**
     * Still available, because on a Laravel-only deployment its lock is a real
     * cross-process guarantee — but opted into rather than inherited.
     */
    public function test_the_cache_store_is_available_on_request(): void
    {
        self::assertInstanceOf(
            CacheCodeStore::class,
            $this->resolve(['code_store' => 'cache', 'permit_local_cache_store' => true]),
        );
    }

    public function test_an_unknown_choice_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->resolve(['code_store' => 'memcached']);
    }

    /**
     * Failing loudly beats silently falling back to an encoding the rest of the
     * ecosystem cannot read.
     */
    public function test_choosing_redis_without_a_redis_connection_is_refused(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->resolve(['code_store' => 'redis'], withRedis: false);
    }

    /**
     * @param  array<string, mixed>  $settings
     */
    private function resolve(array $settings, bool $withRedis = true): mixed
    {
        $app = new Container();

        $app->instance('config', new FakeConfigRepository(['telegram-2fa' => $settings]));

        $app->instance(\Illuminate\Contracts\Cache\Factory::class, new FakeCacheFactory());

        if ($withRedis) {
            $app->instance('redis', new FakeRedisFactory());
        }

        $provider = new TelegramTwoFactorServiceProvider($app);

        // Private because it is an implementation detail of register(); reached
        // directly because the alternative is booting a framework to observe one
        // branch.
        $method = new \ReflectionMethod($provider, 'makeCodeStore');
        $method->setAccessible(true);

        return $method->invoke($provider, $app);
    }
}

/**
 * Enough of Laravel's config repository for the provider, without pulling in
 * illuminate/config.
 */
final class FakeConfigRepository implements \ArrayAccess
{
    /** @param array<string, mixed> $items */
    public function __construct(private array $items) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $segments = explode('.', $key);
        $value = $this->items;

        foreach ($segments as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return $default;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    public function offsetExists(mixed $offset): bool
    {
        return $this->get((string) $offset) !== null;
    }

    public function offsetGet(mixed $offset): mixed
    {
        return $this->get((string) $offset);
    }

    public function offsetSet(mixed $offset, mixed $value): void {}

    public function offsetUnset(mixed $offset): void {}
}

final class FakeCacheFactory implements \Illuminate\Contracts\Cache\Factory
{
    public function store($name = null): \Illuminate\Contracts\Cache\Repository
    {
        return new \Illuminate\Cache\Repository(new \Illuminate\Cache\ArrayStore());
    }
}

/**
 * Stands in for the redis manager. The provider only calls connection() on it,
 * and LaravelRedisCommands only probes the server version — which this answers
 * as something older than 6.2, so the EVAL path is chosen without a server.
 */
final class FakeRedisFactory
{
    public function connection(?string $name = null): \Illuminate\Contracts\Redis\Connection
    {
        return new FakeRedisConnection();
    }
}

final class FakeRedisConnection implements \Illuminate\Contracts\Redis\Connection
{
    public function command($method, array $parameters = []): mixed
    {
        if ($method === 'info') {
            return ['redis_version' => '5.0.10'];
        }

        return null;
    }

    public function subscribe($channels, \Closure $callback): void {}

    public function psubscribe($channels, \Closure $callback): void {}

    public function __call($method, $parameters): mixed
    {
        return $this->command($method, $parameters);
    }
}
