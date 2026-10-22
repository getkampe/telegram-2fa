<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Stores\ArrayCodeStore;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Support\FrozenClock;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * SPEC.md section 9, against the shared fixture in /conformance.
 *
 * The README says the PHP and Node packages can run against one bot and one
 * store. That is a claim about field names and hash construction, and until
 * both suites read the same committed records it is only an assertion — the two
 * implementations shipped with camelCase and snake_case field names, agreed
 * with themselves, and would have silently failed to read each other.
 *
 * The digests in the fixture are literals rather than values either
 * implementation recomputes, because a shared mistake would agree with itself.
 */
final class ConformanceTest extends TestCase
{
    /** @var array<string, mixed> */
    private array $fixture;

    protected function setUp(): void
    {
        parent::setUp();

        $path = __DIR__ . '/../../../conformance/records.json';

        $this->fixture = json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);

        $this->clock = new FrozenClock($this->fixture['now']);
        $this->store = new ArrayCodeStore($this->clock);
        $this->identities = new ArrayIdentityStore($this->clock);
        $this->telegram = new FakeTelegramClient();
        $this->config = $this->config([
            'key_prefix' => $this->fixture['config']['key_prefix'],
            'hash_algorithm' => $this->fixture['config']['hash_algorithm'],
            'hash_pepper' => $this->fixture['config']['hash_pepper'],
        ]);

        $this->tfa = new TelegramTwoFactor(
            $this->config,
            $this->store,
            $this->identities,
            $this->telegram,
            new DefaultMessages(),
            $this->clock,
        );
    }

    public function test_a_challenge_record_written_elsewhere_verifies_here(): void
    {
        $record = $this->fixture['code_record'];

        // Seed the exact enrollment the fixture's challenge belongs to: a
        // challenge from a superseded enrollment is refused, so interop depends
        // on both implementations agreeing about this field too.
        $this->identities->seed($record['user_id'], '555000111', $record['enrollment']);

        $this->store->put($record['key'], $record['value'], 300);

        $this->assertTrue(
            $this->tfa->verify($record['user_id'], $record['plaintext_code'], 'withdrawal')->ok,
            'a record in the shared wire format must verify through the public API'
        );
    }

    public function test_the_key_layout_matches_the_specification(): void
    {
        $this->identities->seed('user-1', '555000111', 'gen-user-1');
        $this->tfa->push('user-1', 'withdrawal');

        // The key the implementation chose must be the key the fixture names.
        $this->assertNotNull($this->store->get($this->fixture['code_record']['key']));
        $this->assertNotNull($this->store->get($this->fixture['cooldown_record']['key']));
    }

    public function test_a_challenge_record_written_here_matches_the_wire_format(): void
    {
        $this->identities->seed('user-1', '555000111', 'gen-user-1');
        $this->tfa->push('user-1', 'withdrawal');

        $written = $this->store->get($this->fixture['code_record']['key']);

        $this->assertIsArray($written);
        $this->assertSame(
            array_keys($this->fixture['code_record']['value']),
            array_keys($written),
            'field names and their order are the wire format of SPEC.md section 9'
        );
    }

    public function test_an_on_demand_record_written_elsewhere_is_general_purpose(): void
    {
        $record = $this->fixture['on_demand_record'];
        $this->identities->seed($record['user_id'], '777000222', $record['enrollment']);

        $this->store->put($record['key'], $record['value'], 300);

        $this->assertTrue(
            $this->tfa->verify($record['user_id'], $record['plaintext_code'], 'login')->ok
        );
    }

    public function test_a_deeplink_record_written_elsewhere_resolves_here(): void
    {
        $record = $this->fixture['deeplink_record'];

        $this->store->put($record['key'], $record['value'], 600);

        $result = $this->tfa->completeDeepLink($record['token'], '888000333');

        $this->assertTrue($result->ok);
        $this->assertSame('888000333', $this->tfa->identity($record['user_id'])?->chatId);
    }

    public function test_a_paste_record_written_elsewhere_resolves_here(): void
    {
        $record = $this->fixture['paste_record'];

        $this->store->put($record['key'], $record['value'], 600);

        $result = $this->tfa->completePasteLink('user-9', $record['token']);

        $this->assertTrue($result->ok);
        $this->assertSame($record['chat_id'], $this->tfa->identity('user-9')?->chatId);
    }

    public function test_the_cooldown_record_is_a_bare_integer(): void
    {
        $this->identities->seed('user-1', '555000111', 'gen-user-1');
        $this->tfa->push('user-1');

        $written = $this->store->get($this->fixture['cooldown_record']['key']);

        // Not an object: the other implementation reads this with Number().
        $this->assertIsInt($written);
        $this->assertSame($this->fixture['cooldown_record']['value'], $written);
    }
}
