<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Codes\CodeGenerator;
use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * SPEC.md sections 2 and 3.
 */
final class LinkingTest extends TestCase
{
    public function test_the_deeplink_flow_links_the_account(): void
    {
        $request = $this->tfa->startDeepLink('user-1');

        $this->assertSame(
            'https://t.me/kampe_test_bot?start=' . $request->token,
            $request->url
        );

        $result = $this->tfa->completeDeepLink($request->token, '555000111');

        $this->assertTrue($result->ok);
        $this->assertTrue($this->tfa->isLinked('user-1'));
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_a_deeplink_token_is_single_use(): void
    {
        $request = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($request->token, '555000111');

        // A second presentation, from a different chat: the obvious attack if
        // the token survives, since the token travels through a chat message.
        $replay = $this->tfa->completeDeepLink($request->token, '999999999');

        $this->assertFalse($replay->ok);
        $this->assertSame(ErrorCode::InvalidToken, $replay->error);
    }

    public function test_an_expired_deeplink_token_is_refused(): void
    {
        $request = $this->tfa->startDeepLink('user-1');

        $this->clock->advance(601);

        $result = $this->tfa->completeDeepLink($request->token, '555000111');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::InvalidToken, $result->error);
    }

    public function test_an_unknown_deeplink_token_is_refused(): void
    {
        $result = $this->tfa->completeDeepLink('not-a-real-token', '555000111');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::InvalidToken, $result->error);
    }

    public function test_the_link_token_is_not_stored_in_plaintext(): void
    {
        $request = $this->tfa->startDeepLink('user-1');

        // The key is derived from the hash, so the raw token must not be a key.
        $this->assertNull($this->store->get($this->config->key('link', $request->token)));
        $this->assertNotNull($this->store->get(
            $this->config->key('link', hash_hmac('sha256', $request->token, ''))
        ));
    }

    public function test_the_paste_flow_links_the_account(): void
    {
        $request = $this->tfa->startPasteLink('555000111');

        $result = $this->tfa->completePasteLink('user-1', $request->token);

        $this->assertTrue($result->ok);
        $this->assertTrue($this->tfa->isLinked('user-1'));
    }

    public function test_a_paste_code_is_accepted_in_lower_case(): void
    {
        $request = $this->tfa->startPasteLink('555000111');

        $result = $this->tfa->completePasteLink('user-1', strtolower($request->token));

        $this->assertTrue($result->ok);
    }

    public function test_a_paste_code_is_long_enough_to_resist_enumeration(): void
    {
        $request = $this->tfa->startPasteLink('555000111');

        // The paste flow's store key is derived from the code, so every
        // outstanding code shares one namespace. Six digits here would be
        // guessable; eight base32 characters is 40 bits.
        $this->assertSame(8, strlen($request->token));
        $this->assertMatchesRegularExpression(
            '/^[' . CodeGenerator::LINK_ALPHABET . ']{8}$/',
            $request->token
        );
    }

    /**
     * One Telegram account as the second factor for several accounts means one
     * compromised Telegram account compromises all of them.
     */
    public function test_a_chat_cannot_become_the_factor_for_a_second_account(): void
    {
        $first = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($first->token, '555000111');

        $second = $this->tfa->startDeepLink('user-2');
        $result = $this->tfa->completeDeepLink($second->token, '555000111');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::AlreadyLinked, $result->error);
        $this->assertFalse($this->tfa->isLinked('user-2'));
        $this->assertSame('user-1', $this->tfa->identityForChat('555000111')?->userId);
    }

    public function test_an_account_cannot_be_moved_to_a_second_chat(): void
    {
        $first = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($first->token, '555000111');

        $second = $this->tfa->startDeepLink('user-1');
        $result = $this->tfa->completeDeepLink($second->token, '777000222');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::AlreadyLinked, $result->error);
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_relinking_the_same_chat_is_idempotent(): void
    {
        $first = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($first->token, '555000111');

        // A user who taps the same link twice, or whose first confirmation was
        // lost, should see success rather than a conflict.
        $second = $this->tfa->startDeepLink('user-1');
        $result = $this->tfa->completeDeepLink($second->token, '555000111');

        $this->assertTrue($result->ok);
    }

    public function test_unlinking_requires_a_valid_code(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $wrong = $this->tfa->unlink('user-1', '000000' === $this->lastCode() ? '111111' : '000000');
        $this->assertFalse($wrong->ok);
        $this->assertTrue($this->tfa->isLinked('user-1'), 'a failed proof must leave the factor in place');
    }

    public function test_unlinking_with_a_valid_code_removes_the_factor(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $result = $this->tfa->unlink('user-1', $this->lastCode());

        $this->assertTrue($result->ok);
        $this->assertFalse($this->tfa->isLinked('user-1'));
    }

    public function test_unlinking_notifies_the_chat(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        // Read the code before clearing the outbox, so that what remains after
        // the unlink is only the notice itself.
        $code = $this->lastCode();
        $this->telegram->reset();

        $this->tfa->unlink('user-1', $code);

        $this->assertSame(1, $this->telegram->messageCount());
        $this->assertStringContainsString('unlinked', strtolower($this->telegram->lastMessage() ?? ''));
    }

    public function test_unlinking_clears_any_code_in_flight(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $this->tfa->unlink('user-1', $this->lastCode());

        $this->assertNull($this->store->get($this->config->key('code', 'user-1')));
        $this->assertNull($this->store->get($this->config->key('cooldown', 'user-1')));
    }

    public function test_external_proof_unlink_is_available_for_recovery(): void
    {
        $this->linked();

        $this->assertTrue($this->tfa->unlinkAfterExternalProof('user-1', 'authenticator app verified'));
        $this->assertFalse($this->tfa->isLinked('user-1'));
    }
}
