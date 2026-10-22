<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Results\LinkRequest;
use Kampe\TelegramTwoFactor\Results\VerificationResult;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * SPEC.md section 3.3: moving the factor to a different Telegram account.
 */
final class ChatReplacementTest extends TestCase
{
    public function test_a_proven_replacement_moves_the_factor(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $result = $this->tfa->completeDeepLink($request->token, '777000222');

        $this->assertTrue($result->ok);
        $this->assertSame('777000222', $this->tfa->identity('user-1')?->chatId);
        $this->assertNull($this->tfa->identityForChat('555000111'));
    }

    public function test_replacement_without_proof_is_refused(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $wrong = $this->lastCode() === '000000' ? '111111' : '000000';

        $result = $this->tfa->startChatReplacement('user-1', $wrong);

        $this->assertInstanceOf(VerificationResult::class, $result);
        $this->assertFalse($result->ok);
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    /**
     * The mark that authorises rebinding lives on the stored token. If it were
     * taken from the resolving call instead, the proof step could be skipped by
     * presenting an ordinary link token.
     */
    public function test_an_ordinary_token_cannot_move_a_verified_binding(): void
    {
        $this->linked();

        $ordinary = $this->tfa->startDeepLink('user-1');
        $result = $this->tfa->completeDeepLink($ordinary->token, '777000222');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::AlreadyLinked, $result->error);
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_replacement_requires_an_existing_link(): void
    {
        $result = $this->tfa->startChatReplacement('user-1', '123456');

        $this->assertInstanceOf(VerificationResult::class, $result);
        $this->assertSame(ErrorCode::NotLinked, $result->error);
    }

    public function test_a_login_code_cannot_authorise_a_replacement(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_LOGIN);

        $result = $this->tfa->startChatReplacement('user-1', $this->lastCode());

        $this->assertInstanceOf(VerificationResult::class, $result);
        $this->assertFalse($result->ok);
    }

    public function test_the_old_chat_is_told_it_is_no_longer_the_factor(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);
        $this->telegram->reset();

        $this->tfa->completeDeepLink($request->token, '777000222');

        // If the user did not request this, that message is how they find out.
        $this->assertSame('555000111', $this->telegram->sent[0]['chat_id']);
        $this->assertStringContainsString('unlinked', strtolower($this->telegram->sent[0]['text']));
    }

    public function test_a_replacement_token_is_still_single_use(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $this->tfa->completeDeepLink($request->token, '777000222');
        $replay = $this->tfa->completeDeepLink($request->token, '888000333');

        $this->assertFalse($replay->ok);
        $this->assertSame('777000222', $this->tfa->identity('user-1')?->chatId);
    }

    /**
     * A refused replacement must not cost the user the factor they already had.
     *
     * Releasing the old binding before checking the destination made a failed
     * request strip the account of its second factor as a side effect — the
     * account was left with no Telegram at all, and depending on policy either
     * locked out or protected by one factor. The old binding is now only
     * released by the same write that takes the new one.
     */
    public function test_a_refused_replacement_leaves_the_original_factor_intact(): void
    {
        $this->linked('user-1', '555000111');
        $this->linked('user-2', '777000222');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $result = $this->tfa->completeDeepLink($request->token, '777000222');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::AlreadyLinked, $result->error);

        // The other account keeps its chat...
        $this->assertSame('user-2', $this->tfa->identityForChat('777000222')?->userId);

        // ...and, the part that was broken, so does this one.
        $this->assertTrue($this->tfa->isLinked('user-1'));
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_a_refused_replacement_does_not_announce_one(): void
    {
        $this->linked('user-1', '555000111');
        $this->linked('user-2', '777000222');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);
        $this->telegram->reset();

        $this->tfa->completeDeepLink($request->token, '777000222');

        // Telling the user their factor was removed when it was not is its own
        // small incident: they will go looking for an attacker.
        $this->assertSame(0, $this->telegram->messageCount());
    }

    /**
     * Authority over a factor must not survive the factor.
     *
     * A replacement token proves possession of one particular binding. Once
     * that binding is gone — recovered through support, unlinked, or already
     * replaced — the proof refers to nothing, and honouring the token would
     * hand whoever holds it whatever binding came next.
     */
    public function test_a_replacement_token_is_void_after_account_recovery(): void
    {
        $this->linked('user-1', '555000111');
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $stale = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $stale);

        // The user loses their Telegram account and support recovers them.
        $this->tfa->unlinkAfterExternalProof('user-1', 'identity verified out of band');

        $fresh = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($fresh->token, '888000333');

        $result = $this->tfa->completeDeepLink($stale->token, '999000444');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::InvalidToken, $result->error);
        $this->assertSame('888000333', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_a_replacement_token_is_void_after_a_completed_replacement(): void
    {
        $this->linked('user-1', '555000111');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $first = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $first);

        $this->clock->advance(121);
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $second = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $second);

        // The second token is used; the first must now be worthless rather than
        // a standing right to move the factor again.
        $this->assertTrue($this->tfa->completeDeepLink($second->token, '777000222')->ok);

        $result = $this->tfa->completeDeepLink($first->token, '888000333');

        $this->assertFalse($result->ok);
        $this->assertSame('777000222', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_a_replacement_token_is_void_after_unlinking(): void
    {
        $this->linked('user-1', '555000111');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $stale = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $stale);

        $this->tfa->unlinkAfterExternalProof('user-1', 'user asked');

        $result = $this->tfa->completeDeepLink($stale->token, '999000444');

        $this->assertFalse($result->ok);
        $this->assertFalse($this->tfa->isLinked('user-1'));
    }

    /**
     * A code already delivered to the old chat is proof held by whoever still
     * has that chat, so it cannot outlive the binding it was sent to.
     */
    public function test_replacement_invalidates_a_code_already_sent_to_the_old_chat(): void
    {
        $this->linked('user-1', '555000111');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $this->clock->advance(121);
        $this->tfa->push('user-1', 'login');
        $inFlight = $this->lastCode();

        $this->assertTrue($this->tfa->completeDeepLink($request->token, '777000222')->ok);

        $this->assertFalse(
            $this->tfa->verify('user-1', $inFlight, 'login')->ok,
            'a code delivered to the replaced chat must not verify afterwards'
        );
    }

    public function test_replacement_clears_the_cooldown_so_the_new_chat_can_be_challenged(): void
    {
        $this->linked('user-1', '555000111');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $this->tfa->completeDeepLink($request->token, '777000222');

        // Otherwise the user has just linked a new chat and must wait out a
        // cooldown earned by the old one before they can prove anything.
        $challenge = $this->tfa->push('user-1', 'login');

        $this->assertTrue($challenge->ok);
        $this->assertSame('777000222', $this->telegram->lastSentTo());
    }
}
