<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests\Integration;

use Kampe\TelegramTwoFactor\Codes\CodeHasher;
use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Stores\PhpRedisCommands;
use Kampe\TelegramTwoFactor\Stores\RedisCodeStore;
use Kampe\TelegramTwoFactor\Support\FrozenClock;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\Tests\FakeTelegramClient;
use Kampe\TelegramTwoFactor\Tests\RecordingRedis;
use PHPUnit\Framework\TestCase;

/**
 * What the shared fixtures could not establish: the bytes this adapter puts on
 * the wire.
 *
 * The /conformance suite checks that a record has the right field names, by
 * seeding an in-memory store. That passes whatever the production adapter does
 * to the value on its way to the server — and Laravel's Redis cache runs it
 * through serialize(), so for a long time this package wrote
 * `a:6:{s:4:"hash";...}` while every other implementation wrote JSON, and the
 * claim that they interoperate was false in exactly the deployment it was made
 * about.
 *
 * So these tests read and write raw bytes against a live server, in both
 * directions, and the fixture is used as what another language would have
 * written.
 *
 * **This suite never flushes.** It would be natural to clear the database
 * between tests; on Redis that is FLUSHDB and it destroys everything, not
 * merely the keys written here. Harmless against a disposable CI container and
 * emphatically not harmless when REDIS_HOST points at a developer's machine. So
 * every key is namespaced under a prefix unique to the run and removed
 * individually.
 */
final class RedisInteropTest extends TestCase
{
    private const PEPPER = 'conformance-fixture-pepper-0123456789abcd';

    private ?\Redis $redis = null;

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

        if (! extension_loaded('redis')) {
            $this->markTestSkipped('ext-redis is not available.');
        }

        $redis = new \Redis();

        try {
            $redis->connect($host, (int) (getenv('REDIS_PORT') ?: 6379), 2.0);
            $redis->select((int) (getenv('REDIS_DB') ?: 0));
            $redis->ping();
        } catch (\Throwable $e) {
            $this->markTestSkipped('Redis is not reachable: ' . $e->getMessage());
        }

        $this->redis = $redis;
        // No colon: Config reserves it as the separator in a store key.
        $this->prefix = 'tg2fa-interop-' . bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach (array_unique($this->touched) as $key) {
            $this->redis?->del($key);
        }

        $this->touched = [];
        $this->redis?->close();

        parent::tearDown();
    }

    private function commands(): PhpRedisCommands
    {
        return new PhpRedisCommands($this->redis);
    }

    private function store(): RedisCodeStore
    {
        return new RedisCodeStore($this->commands());
    }

    private function config(): Config
    {
        return new Config(
            botToken: '123456789:AAFakeTokenForTestsOnly_0123456789abc',
            webhookSecret: str_repeat('s', 48),
            hashPepper: self::PEPPER,
            botUsername: 'kampe_test_bot',
            keyPrefix: $this->prefix,
        );
    }

    private function key(string $name): string
    {
        $this->touched[] = $name;

        return $name;
    }

    // ------------------------------------------------------------ encoding

    /**
     * The regression test for the actual bug.
     */
    public function test_a_record_lands_in_redis_as_json(): void
    {
        $key = $this->key($this->prefix . ':code:user-1');

        $this->store()->put($key, [
            'hash' => 'abc',
            'expires_at' => 1_800_000_300,
            'attempts' => 0,
            'purpose' => 'login',
            'generation' => 'gen',
            'challenge_id' => 'cid',
        ], 60);

        $bytes = $this->redis->get($key);

        self::assertIsString($bytes);
        self::assertStringStartsWith('{', $bytes, 'the wire format of SPEC.md section 9 is JSON');
        self::assertStringNotContainsString(
            'a:6:',
            $bytes,
            'a PHP-serialized record is unreadable to every other implementation',
        );

        $decoded = json_decode($bytes, true, 512, JSON_THROW_ON_ERROR);

        self::assertSame([
            'hash' => 'abc',
            'expires_at' => 1_800_000_300,
            'attempts' => 0,
            'purpose' => 'login',
            'generation' => 'gen',
            'challenge_id' => 'cid',
        ], $decoded);
    }

    /**
     * The other direction: a record written as another language writes it, read
     * through the public API.
     */
    public function test_a_challenge_written_as_json_verifies_through_the_public_api(): void
    {
        $fixture = $this->fixture();
        $record = $fixture['code_record'];
        $config = $this->config();

        $identities = new ArrayIdentityStore();
        $identities->seed($record['user_id'], '555000111', $record['enrollment']);

        // Written as bytes, exactly as a Node or Go process would have left it.
        $key = $this->key($config->key('code', $record['user_id']));
        $this->redis->setex($key, 300, json_encode($record['value'], JSON_THROW_ON_ERROR));

        $tfa = new TelegramTwoFactor(
            config: $config,
            store: $this->store(),
            identities: $identities,
            telegram: new FakeTelegramClient(),
            messages: new DefaultMessages(),
            clock: new FrozenClock($fixture['now']),
        );

        $result = $tfa->verify($record['user_id'], $record['plaintext_code'], 'withdrawal');

        self::assertTrue($result->ok, 'a JSON record from another implementation must verify here');
    }

    /**
     * And a record this package writes must be readable as the fixture's own,
     * field for field, against a live server rather than an array.
     */
    public function test_a_record_written_here_matches_the_fixtures_field_set(): void
    {
        $fixture = $this->fixture();
        $config = $this->config();

        $identities = new ArrayIdentityStore();
        $identities->seed('user-1', '555000111', 'gen-local');

        $tfa = new TelegramTwoFactor(
            config: $config,
            store: $this->store(),
            identities: $identities,
            telegram: new FakeTelegramClient(),
            messages: new DefaultMessages(),
            clock: new FrozenClock($fixture['now']),
        );

        $this->key($config->key('code', 'user-1'));
        $this->key($config->key('cooldown', 'user-1'));

        self::assertTrue($tfa->push('user-1', 'withdrawal')->ok);

        $bytes = $this->redis->get($config->key('code', 'user-1'));
        $written = json_decode((string) $bytes, true, 512, JSON_THROW_ON_ERROR);

        $expected = array_keys($fixture['code_record']['value']);
        $actual = array_keys($written);
        sort($expected);
        sort($actual);

        self::assertSame($expected, $actual);
    }

    /**
     * The cooldown is a bare integer, not an object. A serialising adapter
     * writes i:1800000120; the other implementations read a number.
     */
    public function test_the_cooldown_lands_as_a_bare_number(): void
    {
        $key = $this->key($this->prefix . ':cooldown:user-1');

        $this->store()->put($key, 1_800_000_120, 60);

        self::assertSame('1800000120', $this->redis->get($key));
        self::assertSame(1_800_000_120, $this->store()->get($key));
    }

    // ---------------------------------------------------------- atomicity

    /**
     * Single use across processes, with no lock anywhere.
     *
     * CacheCodeStore gets this right between PHP processes by holding Laravel's
     * named lock. A Node or Go process issues GETDEL and knows nothing about
     * that lock, so the two can interleave and one code can be accepted twice.
     * The fix is for every language to lean on the same server-side operation,
     * and this is that claim tested the only way it can be: separate OS
     * processes, one key, one winner.
     */
    public function test_only_one_of_many_processes_takes_a_value(): void
    {
        $key = $this->key($this->prefix . ':code:race');
        $this->redis->setex($key, 60, '{"hash":"only-one-may-have-this"}');

        self::assertSame(1, $this->raceProcesses($key, 8), 'exactly one process may receive the value');
        self::assertFalse($this->redis->exists($key) > 0, 'and the key is gone');
    }

    /**
     * The reservation half, the same way: SET NX decided by the server.
     */
    public function test_only_one_of_many_processes_wins_a_reservation(): void
    {
        $key = $this->key($this->prefix . ':cooldown:race');

        self::assertSame(1, $this->raceProcesses($key, 8, 'add'), 'exactly one reservation may win');
    }

    /**
     * Spawn $count processes against one key, release them together, and return
     * how many reported a win.
     *
     * Corroboration rather than proof. It passes, and it did not catch a
     * client-side GET-then-DEL when that was tried as a mutation: the two
     * commands complete inside one round trip, so eight processes reliably miss
     * each other. The decisive test is the command-level one above, which
     * asserts there is only ever one command to interleave with. This exists
     * because a real server and real processes can still surprise you, and
     * nothing here is slow.
     *
     * @return int
     */
    private function raceProcesses(string $key, int $count, string $mode = 'take'): int
    {
        $script = $this->raceScript();
        $go = $this->key($this->prefix . ':go:' . bin2hex(random_bytes(3)));

        $processes = [];
        $pipes = [];

        for ($i = 0; $i < $count; $i++) {
            $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open(
                [PHP_BINARY, $script, $key, $mode, $go],
                $descriptors,
                $pipes[$i],
            );

            if ($process === false) {
                self::markTestSkipped('Could not spawn a PHP subprocess.');
            }

            $processes[$i] = $process;
        }

        // Long enough for every process to boot, connect and reach its spin
        // loop. They then all see the key on the same poll.
        usleep(400_000);
        $this->redis->setex($go, 30, '1');

        $winners = 0;

        foreach ($processes as $i => $process) {
            $output = trim((string) stream_get_contents($pipes[$i][1]));
            fclose($pipes[$i][1]);
            fclose($pipes[$i][2]);
            proc_close($process);

            if ($output === 'won') {
                $winners++;
            }
        }

        return $winners;
    }

    /**
     * take() is one command, and this watches the commands.
     *
     * The decisive test for the property every language depends on. An earlier
     * version of it counted calls on the RedisCommands wrapper, which sees one
     * getDelete() whether that method issues GETDEL or a client-side GET
     * followed by a DEL - so it passed against exactly the bug it existed to
     * catch. A mutation run found that. This recorder sits underneath, where the
     * commands are.
     */
    public function test_take_issues_one_command_to_the_server(): void
    {
        $key = $this->key($this->prefix . ':code:single-op');
        $this->redis->setex($key, 60, '{"hash":"x"}');

        $recorder = new RecordingRedis($this->redis);

        // The fallback path, which is what an older server runs.
        $store = new RedisCodeStore(new PhpRedisCommands($recorder, hasGetDel: false));
        $recorder->reset();

        self::assertSame(['hash' => 'x'], $store->take($key));
        self::assertSame(
            ['EVAL'],
            $recorder->commands,
            'a GET followed by a DEL cannot be atomic, whatever this process locks',
        );
    }

    public function test_take_issues_one_command_on_the_getdel_path(): void
    {
        if (! method_exists($this->redis, 'getDel')) {
            self::markTestSkipped('This phpredis build has no getDel().');
        }

        if (version_compare($this->serverVersion(), '6.2.0', '<')) {
            self::markTestSkipped('This server predates GETDEL; the EVAL path is covered above.');
        }

        $key = $this->key($this->prefix . ':code:getdel-op');
        $this->redis->setex($key, 60, '{"hash":"x"}');

        $recorder = new RecordingRedis($this->redis);
        $store = new RedisCodeStore(new PhpRedisCommands($recorder, hasGetDel: true));
        $recorder->reset();

        self::assertSame(['hash' => 'x'], $store->take($key));
        self::assertSame(['GETDEL'], $recorder->commands);
    }

    /**
     * And the reservation is one command too, not a read followed by a write.
     */
    public function test_add_issues_one_command_to_the_server(): void
    {
        $key = $this->key($this->prefix . ':cooldown:single-op');

        $recorder = new RecordingRedis($this->redis);
        $store = new RedisCodeStore(new PhpRedisCommands($recorder, hasGetDel: false));
        $recorder->reset();

        self::assertTrue($store->add($key, 1, 60));
        self::assertSame(['SET NX'], $recorder->commands);
    }

    /**
     * On this server the EVAL fallback is what runs, because GETDEL arrived in
     * Redis 6.2. Either path must behave identically, so assert the behaviour
     * with the fallback forced on.
     */
    public function test_the_eval_fallback_takes_a_value_exactly_once(): void
    {
        $key = $this->key($this->prefix . ':code:eval');
        $this->redis->setex($key, 60, '{"hash":"y"}');

        $store = new RedisCodeStore(new PhpRedisCommands($this->redis, hasGetDel: false));

        self::assertSame(['hash' => 'y'], $store->take($key));
        self::assertNull($store->take($key), 'the second take has nothing to find');
    }

    // ------------------------------------------------------------- helpers

    /**
     * A record this library did not write must read as absent rather than
     * throw. A cache-backed record left over from before a migration is exactly
     * this case.
     */
    public function test_a_php_serialized_leftover_reads_as_absent(): void
    {
        $key = $this->key($this->prefix . ':code:leftover');
        $this->redis->setex($key, 60, 'a:1:{s:4:"hash";s:3:"abc";}');

        self::assertNull($this->store()->get($key));
        self::assertNull($this->store()->take($key));
    }

    public function test_a_digest_written_here_matches_the_committed_fixture(): void
    {
        $fixture = $this->fixture();
        $record = $fixture['code_record'];

        $hasher = new CodeHasher('sha256', self::PEPPER);

        self::assertSame(
            $record['value']['hash'],
            $hasher->hash($record['plaintext_code'], $record['user_id']),
            'the digest construction is part of the wire format',
        );
    }

    public function test_an_unreachable_reservation_reports_false(): void
    {
        $key = $this->key($this->prefix . ':cooldown:twice');
        $store = $this->store();

        self::assertTrue($store->add($key, 1, 60));
        self::assertFalse($store->add($key, 2, 60), 'the loser must be told it lost');
        self::assertSame(1, $store->get($key), 'and must not have overwritten the winner');
    }

    private function serverVersion(): string
    {
        /** @var array<string, mixed>|false $info */
        $info = $this->redis?->info('SERVER');
        $version = is_array($info) ? ($info['redis_version'] ?? null) : null;

        return is_string($version) ? $version : '0.0.0';
    }

    /** @return array<string, mixed> */
    private function fixture(): array
    {
        $path = __DIR__ . '/../../../../conformance/records.json';
        $raw = file_get_contents($path);

        self::assertIsString($raw, 'the shared fixture must be readable');

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /**
     * The subprocess used by the race tests, written once to a temp file.
     */
    private function raceScript(): string
    {
        $path = sys_get_temp_dir() . '/tg2fa-race-' . bin2hex(random_bytes(4)) . '.php';
        $autoload = __DIR__ . '/../../vendor/autoload.php';
        $host = getenv('REDIS_HOST') ?: '127.0.0.1';
        $port = (int) (getenv('REDIS_PORT') ?: 6379);
        $database = (int) (getenv('REDIS_DB') ?: 0);

        $source = <<<PHP
            <?php
            require '{$autoload}';

            use Kampe\TelegramTwoFactor\Stores\PhpRedisCommands;
            use Kampe\TelegramTwoFactor\Stores\RedisCodeStore;

            \$key = \$argv[1];
            \$mode = \$argv[2] ?? 'take';

            \$redis = new Redis();
            \$redis->connect('{$host}', {$port}, 2.0);
            \$redis->select({$database});

            \$store = new RedisCodeStore(new PhpRedisCommands(\$redis));

            // Connect, compile, then spin until the parent fires the start
            // gun. Sleeping a fixed amount instead leaves the processes spread
            // over whatever the slowest startup took, which is a sequence
            // wearing a race's clothes.
            \$go = \$argv[3] ?? null;

            if (\$go !== null) {
                \$deadline = microtime(true) + 5.0;

                while (\$redis->exists(\$go) === 0 && microtime(true) < \$deadline) {
                    // Busy, deliberately: a sleep here is a sleep in the window
                    // this test is trying to keep open.
                }
            }

            if (\$mode === 'add') {
                echo \$store->add(\$key, 'mine', 60) ? 'won' : 'lost';
            } else {
                echo \$store->take(\$key) === null ? 'lost' : 'won';
            }
            PHP;

        file_put_contents($path, $source);

        register_shutdown_function(static function () use ($path): void {
            @unlink($path);
        });

        return $path;
    }
}
