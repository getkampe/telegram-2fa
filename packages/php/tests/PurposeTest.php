<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * SPEC.md sections 4.1, 4.2 and 5: a code authorises the step it was issued for
 * and no other, and the check cannot be skipped.
 */
final class PurposeTest extends TestCase
{
    public function test_a_pushed_code_satisfies_its_own_purpose(): void
    {
        $this->linked();
        $this->tfa->push('user-1', 'withdrawal');

        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode(), 'withdrawal')->ok);
    }

    public function test_a_pushed_code_does_not_satisfy_another_purpose(): void
    {
        $this->linked();
        $this->tfa->push('user-1', 'login');

        $result = $this->tfa->verify('user-1', $this->lastCode(), 'withdrawal');

        $this->assertFalse($result->ok);
    }

    /**
     * The hole this test exists for: when the purpose argument was optional and
     * defaulted to "compare against nothing", a login code approved a
     * withdrawal at any call site that forgot to pass the purpose through — and
     * that call site is both invisible and the one that matters.
     */
    public function test_a_login_code_cannot_approve_a_privileged_step_by_omission(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_LOGIN);
        $code = $this->lastCode();

        // The verification a withdrawal endpoint performs.
        $this->assertFalse($this->tfa->verify('user-1', $code, 'withdrawal')->ok);

        // And the default is login, not "anything".
        $this->tfa->push('user-1', 'withdrawal');
        $this->clock->advance(121);
        $this->tfa->push('user-1', 'withdrawal');

        $this->assertFalse(
            $this->tfa->verify('user-1', $this->lastCode())->ok,
            'omitting the purpose must mean login, never a wildcard'
        );
    }

    /**
     * A code the user fetched with /code cannot know what it is for, so it is
     * the one general-purpose code in the protocol.
     */
    public function test_an_on_demand_code_satisfies_any_purpose(): void
    {
        $this->linked();

        $this->tfa->pull('555000111');
        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode(), 'withdrawal')->ok);

        $this->clock->advance(121);

        $this->tfa->pull('555000111');
        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode(), 'login')->ok);
    }

    public function test_a_purpose_mismatch_reports_invalid_and_not_its_own_error(): void
    {
        $this->linked();
        $this->tfa->push('user-1', 'login');

        $result = $this->tfa->verify('user-1', $this->lastCode(), 'withdrawal');

        // Reporting the mismatch distinctly would tell a caller that a live
        // code exists for a different step, which it has not proved it may know.
        $this->assertSame(ErrorCode::Invalid, $result->error);
    }

    public function test_a_purpose_mismatch_spends_an_attempt(): void
    {
        $this->linked();
        $this->tfa->push('user-1', 'login');
        $code = $this->lastCode();

        // Otherwise the mismatch path is a free, unbudgeted oracle.
        $this->assertSame(4, $this->tfa->verify('user-1', $code, 'withdrawal')->attemptsRemaining);
        $this->assertSame(3, $this->tfa->verify('user-1', $code, 'withdrawal')->attemptsRemaining);
    }

    public function test_unlinking_rejects_a_code_pushed_for_a_login(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_LOGIN);

        $result = $this->tfa->unlink('user-1', $this->lastCode());

        $this->assertFalse($result->ok);
        $this->assertTrue($this->tfa->isLinked('user-1'));
    }

    public function test_unlinking_accepts_a_code_the_user_fetched(): void
    {
        $this->linked();
        $this->tfa->pull('555000111');

        $this->assertTrue($this->tfa->unlink('user-1', $this->lastCode())->ok);
        $this->assertFalse($this->tfa->isLinked('user-1'));
    }

    public function test_unlinking_accepts_a_code_pushed_for_unlinking(): void
    {
        $this->linked();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_UNLINK);

        $this->assertTrue($this->tfa->unlink('user-1', $this->lastCode())->ok);
    }
}
