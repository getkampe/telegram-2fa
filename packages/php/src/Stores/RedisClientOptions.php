<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Exceptions\ConfigurationError;

/**
 * Checks that a Redis client is configured in a way the other implementations
 * can read.
 *
 * Talking to a connection rather than to Laravel's cache removes the cache's own
 * serialization, and that is all it removes. A phpredis client carries its own
 * options, and Laravel sets them straight from config:
 *
 * - OPT_SERIALIZER and OPT_COMPRESSION transform every value on the way in and
 *   out. The round trip is consistent for this process, so nothing looks wrong
 *   from PHP — and the bytes in Redis are a serialized or deflated wrapper
 *   around the JSON, which no other implementation can read. Always refused.
 * - OPT_PREFIX is prepended to every key. A default Laravel application sets
 *   one: `REDIS_PREFIX`, which defaults to "<app_name>_database_". So the
 *   record the specification calls `tg2fa:code:user-1` is physically stored at
 *   `laravel_database_tg2fa:code:user-1`, and a Node process looking where the
 *   specification says to look finds nothing. Refused unless the caller says it
 *   is intended.
 *
 * A prefix is not wrong in itself. On a deployment where every process is PHP it
 * is harmless, and in a mixed deployment it is fine as long as every client
 * applies the same one. What is not acceptable is for it to apply silently while
 * the package claims the implementations share a store, so it has to be
 * acknowledged rather than inherited.
 */
final class RedisClientOptions
{
    /**
     * @param  object  $client  A \Redis, or anything exposing getOption().
     *
     * @throws ConfigurationError
     */
    public static function assertInteroperable(object $client, bool $allowKeyPrefix = false): void
    {
        if (! class_exists(\Redis::class) || ! method_exists($client, 'getOption')) {
            // Nothing to read. Saying so would be noise on a client this check
            // was not written for; the adapter's own contract still stands.
            return;
        }

        self::assertNoTransform(
            $client,
            \Redis::OPT_SERIALIZER,
            'serializer',
            'Every value would be wrapped before it reached Redis, so the bytes would not be '
            . 'the JSON of SPEC.md section 9. The round trip is consistent within PHP, which is '
            . 'what makes this worth refusing rather than leaving to be discovered.',
        );

        self::assertNoTransform(
            $client,
            \Redis::OPT_COMPRESSION,
            'compression',
            'Every value would be deflated before it reached Redis, so no other implementation '
            . 'could read it.',
        );

        if ($allowKeyPrefix) {
            return;
        }

        $prefix = self::option($client, \Redis::OPT_PREFIX);

        if (is_string($prefix) && $prefix !== '') {
            throw new ConfigurationError(sprintf(
                'This Redis client prepends "%s" to every key, so a record the specification '
                . 'calls "tg2fa:code:<user>" is physically stored at "%stg2fa:code:<user>" and the '
                . 'Node, Python, Ruby and C# implementations will not find it. A default Laravel '
                . 'application sets this from REDIS_PREFIX. Either clear the prefix on the '
                . 'connection this package uses and namespace with Config::$keyPrefix instead, '
                . 'which every implementation honours, or acknowledge it: pass $allowKeyPrefix, '
                . 'or set telegram-2fa.allow_redis_key_prefix, if every client reading these keys '
                . 'applies the same prefix. On a PHP-only deployment it is harmless.',
                $prefix,
                $prefix,
            ));
        }
    }

    /**
     * Predis keeps its prefix in an options object rather than on the client.
     *
     * @throws ConfigurationError
     */
    public static function assertNoPredisPrefix(object $client, bool $allowKeyPrefix = false): void
    {
        if ($allowKeyPrefix || ! method_exists($client, 'getOptions')) {
            return;
        }

        try {
            $options = $client->getOptions();
            /** @var mixed $prefix */
            $prefix = is_object($options) && property_exists($options, 'prefix') ? $options->prefix : null;
        } catch (\Throwable) {
            return;
        }

        if ($prefix === null) {
            return;
        }

        $text = is_object($prefix) && method_exists($prefix, 'getPrefix')
            ? (string) $prefix->getPrefix()
            : (is_scalar($prefix) ? (string) $prefix : '');

        if ($text !== '') {
            throw new ConfigurationError(sprintf(
                'This Redis client prepends "%s" to every key, so the other implementations will '
                . 'not find these records where the specification says they are. Clear the prefix, '
                . 'or acknowledge it with $allowKeyPrefix if every client applies the same one.',
                $text,
            ));
        }
    }

    private static function assertNoTransform(object $client, int $option, string $name, string $why): void
    {
        $value = self::option($client, $option);

        // 0 is Redis::SERIALIZER_NONE and Redis::COMPRESSION_NONE alike.
        if ($value === null || (int) $value === 0) {
            return;
        }

        throw new ConfigurationError(sprintf(
            'This Redis client has a %s configured (%s). %s Remove it from the connection this '
            . 'package uses — give it its own connection if the rest of the application needs one.',
            $name,
            (string) (int) $value,
            $why,
        ));
    }

    private static function option(object $client, int $option): mixed
    {
        try {
            /** @var mixed $value */
            $value = $client->getOption($option);
        } catch (\Throwable) {
            return null;
        }

        return $value === false ? null : $value;
    }
}
