<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * SPEC.md sections 4, 5 and 6.
 */
final class ChallengeTest extends TestCase
{
    public function test_push_sends_a_code_to_the_linked_chat(): void
    {
        $this->linked();

        $result = $this->tfa->push('user-1');

        $this->assertTrue($result->ok);
        $this->assertSame(1, $this->telegram->messageCount());
        $this->assertSame('555000111', $this->telegram->sent[0]['chat_id']);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $this->lastCode());
    }

    public function test_push_refuses_an_unlinked_account(): void
    {
        $result = $this->tfa->push('nobody');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::NotLinked, $result->error);
        $this->assertSame(0, $this->telegram->messageCount());
    }

    public function test_an_unverified_link_is_not_a_second_factor(): void
    {
        // A chat id present with no verification timestamp: a link that was
        // started and never finished.
        $store = new class implements \Kampe\TelegramTwoFactor\Contracts\IdentityStore {
            public function findByUserId(string $userId): ?\Kampe\TelegramTwoFactor\Results\Identity
            {
                return new \Kampe\TelegramTwoFactor\Results\Identity($userId, '999', null, 'gen-1');
            }

            public function findByChatId(string $chatId): ?\Kampe\TelegramTwoFactor\Results\Identity
            {
                return new \Kampe\TelegramTwoFactor\Results\Identity('user-1', $chatId, null, 'gen-1');
            }

            public function transition(
                string $userId,
                ?string $chatId,
                ?string $expected,
                string $next,
            ): ?\Kampe\TelegramTwoFactor\Results\Identity {
                return new \Kampe\TelegramTwoFactor\Results\Identity($userId, $chatId, 1, $next);
            }
        };

        $tfa = new \Kampe\TelegramTwoFactor\TelegramTwoFactor(
            $this->config,
            $this->store,
            $store,
            $this->telegram,
            new \Kampe\TelegramTwoFactor\Telegram\DefaultMessages(),
            $this->clock,
        );

        $result = $tfa->push('user-1');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::NotLinked, $result->error);
    }

    public function test_the_code_never_appears_in_the_result(): void
    {
        $this->linked();

        $result = $this->tfa->push('user-1');

        // Belt and braces: the result is routinely returned straight to an HTTP
        // client, so assert on its serialised form rather than its properties.
        $this->assertStringNotContainsString($this->lastCode(), json_encode($result->toArray()));
    }

    public function test_a_second_request_inside_the_cooldown_is_refused(): void
    {
        $this->linked();

        $this->tfa->push('user-1');
        $second = $this->tfa->push('user-1');

        $this->assertFalse($second->ok);
        $this->assertSame(ErrorCode::Cooldown, $second->error);
        $this->assertSame(120, $second->retryAfter($this->clock->now()));
        $this->assertSame(1, $this->telegram->messageCount());
    }

    public function test_a_request_after_the_cooldown_is_allowed(): void
    {
        $this->linked();

        $this->tfa->push('user-1');
        $this->clock->advance(121);
        $second = $this->tfa->push('user-1');

        $this->assertTrue($second->ok);
        $this->assertSame(2, $this->telegram->messageCount());
    }

    /**
     * A code the user never received must not occupy the slot, or the account
     * is stuck until the cooldown expires with no way to try again.
     */
    public function test_a_failed_delivery_leaves_no_live_code_and_no_cooldown(): void
    {
        $this->linked();
        $this->telegram->shouldFailSending = true;

        $result = $this->tfa->push('user-1');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::SendFailed, $result->error);

        $this->telegram->shouldFailSending = false;
        $retry = $this->tfa->push('user-1');

        $this->assertTrue($retry->ok, 'a retry should be possible immediately after a delivery failure');
    }

    public function test_pull_issues_a_code_for_a_known_chat(): void
    {
        $this->linked();

        $result = $this->tfa->pull('555000111');

        $this->assertTrue($result->ok);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $this->lastCode());
    }

    public function test_pull_refuses_an_unknown_chat(): void
    {
        $result = $this->tfa->pull('404404404');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::NotLinked, $result->error);
    }

    /**
     * The single-key rule of SPEC.md section 4: one verification call accepts a
     * code from either direction. An implementation that writes one key on push
     * and reads another passes every pull-path test and fails every real push.
     */
    public function test_a_pushed_code_and_a_pulled_code_verify_through_the_same_call(): void
    {
        $this->linked();

        $this->tfa->push('user-1');
        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode())->ok);

        $this->clock->advance(121);

        $this->tfa->pull('555000111');
        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode())->ok);
    }

    public function test_codes_are_stored_hashed(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $record = $this->store->get($this->config->key('code', 'user-1'));

        $this->assertIsArray($record);
        $this->assertArrayNotHasKey('code', $record);
        $this->assertNotSame($this->lastCode(), $record['hash']);
        $this->assertSame(64, strlen((string) $record['hash']), 'sha256 hmac, hex encoded');
    }
}
