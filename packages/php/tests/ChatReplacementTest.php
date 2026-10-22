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

    public function test_replacement_cannot_take_a_chat_that_belongs_to_someone_else(): void
    {
        $this->linked('user-1', '555000111');
        $this->linked('user-2', '777000222');

        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);
        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        $result = $this->tfa->completeDeepLink($request->token, '777000222');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::AlreadyLinked, $result->error);
        $this->assertSame('user-2', $this->tfa->identityForChat('777000222')?->userId);
    }
}
