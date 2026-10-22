<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\ErrorCode;

/**
 * SPEC.md section 5.
 */
final class VerificationTest extends TestCase
{
    public function test_the_right_code_passes(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $this->assertTrue($this->tfa->verify('user-1', $this->lastCode())->ok);
    }

    public function test_a_wrong_code_fails_and_spends_an_attempt(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $result = $this->tfa->verify('user-1', '000000' === $this->lastCode() ? '111111' : '000000');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::Invalid, $result->error);
        $this->assertSame(4, $result->attemptsRemaining);
    }

    public function test_a_code_works_only_once(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();

        $this->assertTrue($this->tfa->verify('user-1', $code)->ok);

        $replay = $this->tfa->verify('user-1', $code);

        $this->assertFalse($replay->ok, 'a verified code must not verify a second time');
        $this->assertSame(ErrorCode::Expired, $replay->error);
    }

    public function test_the_attempt_budget_kills_the_code(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();
        $wrong = $code === '000000' ? '111111' : '000000';

        for ($i = 0; $i < 4; $i++) {
            $this->assertSame(ErrorCode::Invalid, $this->tfa->verify('user-1', $wrong)->error);
        }

        $fifth = $this->tfa->verify('user-1', $wrong);
        $this->assertSame(ErrorCode::TooManyAttempts, $fifth->error);

        // And the real code is dead too, which is the point: the budget belongs
        // to the code, not to the attacker.
        $this->assertFalse($this->tfa->verify('user-1', $code)->ok);
    }

    public function test_an_expired_code_fails(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();

        $this->clock->advance(301);

        $result = $this->tfa->verify('user-1', $code);

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::Expired, $result->error);
    }

    /**
     * Re-storing the record on a failed attempt must not extend its life, or an
     * attacker can keep a code alive indefinitely by guessing wrong, and the
     * time limit stops existing.
     */
    public function test_a_wrong_guess_does_not_extend_the_codes_life(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();
        $wrong = $code === '000000' ? '111111' : '000000';

        $this->clock->advance(200);
        $this->tfa->verify('user-1', $wrong);

        $this->clock->advance(101); // 301s since issue
        $this->assertSame(ErrorCode::Expired, $this->tfa->verify('user-1', $code)->error);
    }

    public function test_verification_with_no_code_in_flight_reports_expired(): void
    {
        $this->linked();

        $result = $this->tfa->verify('user-1', '123456');

        $this->assertFalse($result->ok);
        $this->assertSame(ErrorCode::Expired, $result->error);
    }

    public function test_whitespace_around_a_pasted_code_is_tolerated(): void
    {
        $this->linked();
        $this->tfa->push('user-1');

        $this->assertTrue($this->tfa->verify('user-1', ' ' . $this->lastCode() . "\n")->ok);
    }

    /**
     * A code issued to confirm a login should not also confirm a withdrawal.
     */
    public function test_a_code_issued_for_one_purpose_does_not_satisfy_another(): void
    {
        $this->linked();
        $this->tfa->push('user-1', 'login');
        $code = $this->lastCode();

        $wrongPurpose = $this->tfa->verify('user-1', $code, 'withdrawal');
        $this->assertFalse($wrongPurpose->ok);

        $rightPurpose = $this->tfa->verify('user-1', $code, 'login');
        $this->assertTrue($rightPurpose->ok);
    }

    /**
     * PHP's == compares two numeric strings as numbers, so '0123456' and
     * '123456.0' are equal under it. Comparing hex digests with hash_equals
     * removes both that and the timing side channel.
     */
    public function test_a_numerically_equal_but_textually_different_code_fails(): void
    {
        $this->linked();
        $this->tfa->push('user-1');
        $code = $this->lastCode();

        $variants = [
            ltrim($code, '0') === '' ? '0' : ltrim($code, '0'),
            $code . '.0',
            '0' . $code,
            ' 0x' . $code,
        ];

        foreach ($variants as $variant) {
            if ($variant === $code) {
                continue;
            }

            $this->assertFalse(
                $this->tfa->verify('user-1', $variant)->ok,
                sprintf('"%s" must not verify against "%s"', $variant, $code)
            );
        }
    }
}
