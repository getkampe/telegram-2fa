<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Stores\ArrayCodeStore;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * SPEC.md section 5.1: the state transitions that must be atomic.
 *
 * Single use and the attempt budget are the two things standing between a
 * six-digit code and an attacker, and both are read-modify-write sequences. If
 * the store is allowed to interleave them, a code verifies twice and wrong
 * guesses stop being counted.
 */
final class ConcurrencyTest extends TestCase
{
    private InterleavingCodeStore $racing;

    protected function setUp(): void
    {
        parent::setUp();

        $this->racing = new InterleavingCodeStore(new ArrayCodeStore($this->clock));
        $this->identities = new ArrayIdentityStore($this->clock);

        $this->tfa = new TelegramTwoFactor(
            $this->config,
            $this->racing,
            $this->identities,
            $this->telegram,
            new DefaultMessages(),
            $this->clock,
        );
    }

    public function test_one_code_cannot_verify_twice_concurrently(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();

        $second = null;

        // Fire a competing verification from inside the first one's window.
        $this->racing->interleaveOnTake(
            $this->config->key('code', 'user-1'),
            function () use ($code, &$second): void {
                $second = $this->tfa->verify('user-1', $code);
            }
        );

        $first = $this->tfa->verify('user-1', $code);

        $this->assertTrue($first->ok);
        $this->assertNotNull($second);
        $this->assertFalse($second->ok, 'a single-use code must not succeed twice under concurrency');
        $this->assertSame(ErrorCode::Expired, $second->error);
    }

    public function test_a_wrong_guess_cannot_be_lost_to_a_concurrent_one(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $wrong = $this->lastCode() === '000000' ? '111111' : '000000';

        $inner = null;

        $this->racing->interleaveOnTake(
            $this->config->key('code', 'user-1'),
            function () use ($wrong, &$inner): void {
                $inner = $this->tfa->verify('user-1', $wrong);
            }
        );

        $outer = $this->tfa->verify('user-1', $wrong);

        // Both failed, and the budget reflects both — a lost update here would
        // make the five-attempt limit unenforceable by simply racing it.
        $this->assertFalse($outer->ok);
        $this->assertNotNull($inner);
        $this->assertFalse($inner->ok);

        $record = $this->racing->get($this->config->key('code', 'user-1'));

        $this->assertIsArray($record);
        $this->assertSame(1, $record['attempts'], 'the inner attempt holds the record, the outer finds none');
    }

    public function test_two_concurrent_challenges_send_one_code(): void
    {
        $this->linked();

        $second = null;

        // The window a check-then-write cooldown would lose: both callers look,
        // neither sees a cooldown, both send.
        $this->racing->interleaveOnAdd(
            $this->config->key('cooldown', 'user-1'),
            function () use (&$second): void {
                $second = $this->tfa->push('user-1');
            }
        );

        $first = $this->tfa->push('user-1');

        $this->assertNotNull($second);
        $this->assertNotSame(
            $first->ok,
            $second->ok,
            'exactly one of two concurrent challenges may win the cooldown'
        );
        $this->assertSame(1, $this->telegram->messageCount());
    }

    public function test_a_link_token_cannot_be_resolved_twice_concurrently(): void
    {
        $request = $this->tfa->startDeepLink('user-1');

        $second = null;

        // Any link key: the token's hash is not exposed, and a test should not
        // reimplement the derivation to find out.
        $this->racing->interleaveOnTake(
            $this->config->keyPrefix . ':link:',
            function () use ($request, &$second): void {
                $second = $this->tfa->completeDeepLink($request->token, '999000111');
            }
        );

        $first = $this->tfa->completeDeepLink($request->token, '555000111');

        $this->assertTrue($first->ok);
        $this->assertNotNull($second);
        $this->assertFalse($second->ok, 'a link token must bind exactly one chat');
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }
}
