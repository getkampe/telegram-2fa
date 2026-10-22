<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\ErrorCode;
use Kampe\TelegramTwoFactor\Results\LinkRequest;
use Kampe\TelegramTwoFactor\Stores\ArrayCodeStore;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;

/**
 * SPEC.md sections 2 and 5.1: the interleavings between an enrollment change
 * and whatever is holding authority over the enrollment it replaces.
 *
 * Every case here fires a second operation from inside the first one's window
 * through a deterministic hook, never a sleep. Each is checked against the
 * protection being removed — see the suite's own notes — because a race test
 * that passes either way tests nothing.
 */
final class TransitionRaceTest extends TestCase
{
    private InterleavingIdentityStore $racingIdentities;

    protected function setUp(): void
    {
        parent::setUp();

        $this->racingIdentities = new InterleavingIdentityStore(
            new ArrayIdentityStore($this->clock)
        );

        $this->tfa = new TelegramTwoFactor(
            $this->config,
            $this->store,
            $this->racingIdentities,
            $this->telegram,
            new DefaultMessages(),
            $this->clock,
        );
    }

    private function seed(string $userId = 'user-1', string $chatId = '555000111'): void
    {
        $this->racingIdentities->inner()->seed($userId, $chatId, 'gen-initial');
    }

    /**
     * The gap the conditional transition exists to close: validation of a
     * replacement token succeeds, a recovery lands, and the binding write then
     * applies to an enrollment the token never proved.
     */
    public function test_recovery_between_validation_and_the_write_rejects_the_stale_token(): void
    {
        $this->seed();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $request = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $request);

        // Fire the recovery after the token has been validated, inside the
        // transition that would bind the new chat.
        $this->racingIdentities->interleaveOnTransition(function (): void {
            $this->tfa->unlinkAfterExternalProof('user-1', 'support recovered the account');
            $fresh = $this->tfa->startDeepLink('user-1');
            $this->tfa->completeDeepLink($fresh->token, '888000333');
        });

        $result = $this->tfa->completeDeepLink($request->token, '999000444');

        $this->assertFalse($result->ok, 'a token proved against a superseded enrollment must fail');
        $this->assertSame(ErrorCode::InvalidToken, $result->error);
        $this->assertSame(
            '888000333',
            $this->tfa->identity('user-1')?->chatId,
            'the recovered enrollment must survive the stale write'
        );
    }

    /**
     * The verification window: the record has been taken, a recovery revokes
     * it, and the failed-attempt path then writes it back.
     */
    public function test_recovery_between_taking_a_code_and_restoring_it_cannot_resurrect_it(): void
    {
        $this->seed();
        $this->tfa->push('user-1');
        $code = $this->lastCode();
        $wrong = $code === '000000' ? '111111' : '000000';

        $racingStore = new InterleavingCodeStore($this->store);
        $tfa = new TelegramTwoFactor(
            $this->config,
            $racingStore,
            $this->racingIdentities,
            $this->telegram,
            new DefaultMessages(),
            $this->clock,
        );

        // Revoke while the first verification holds the only copy.
        $racingStore->interleaveOnTake(
            $this->config->key('code', 'user-1'),
            function (): void {
                $this->tfa->unlinkAfterExternalProof('user-1', 'support recovered the account');
                $fresh = $this->tfa->startDeepLink('user-1');
                $this->tfa->completeDeepLink($fresh->token, '888000333');
            }
        );

        // A wrong guess, so the failed-attempt path runs and writes the record
        // back after the revocation.
        $tfa->verify('user-1', $wrong);

        // Whether or not the write happened, the code must be unusable: the
        // enrollment it belonged to no longer exists.
        $this->assertFalse(
            $tfa->verify('user-1', $code)->ok,
            'a code from a superseded enrollment must never be accepted'
        );
    }

    /**
     * The guarantee stated in the design: preventing a stale record from being
     * written back is best-effort, but accepting one is impossible.
     *
     * So put the stale record back by hand — exactly what a lost race would do
     * — and require that it still cannot authorise anything. This isolates the
     * acceptance check; the case above is satisfied by the restore guard alone,
     * which is the weaker of the two protections.
     */
    public function test_a_stale_record_is_inert_even_when_written_back(): void
    {
        $this->seed();
        $this->tfa->push('user-1');
        $code = $this->lastCode();

        $key = $this->config->key('code', 'user-1');
        $record = $this->store->get($key);

        // Revoke the enrollment the record belongs to.
        $this->tfa->unlinkAfterExternalProof('user-1', 'support recovered the account');
        $fresh = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($fresh->token, '888000333');

        // Resurrect it.
        $this->store->put($key, $record, 300);

        $this->assertFalse(
            $this->tfa->verify('user-1', $code)->ok,
            'a record from a superseded enrollment must be inert even if restored'
        );
    }

    /**
     * What the timestamp fingerprint could not express. Unlinking and relinking
     * the same chat inside one second produced an identical `chat_id|linked_at`
     * pair, so authority minted before the unlink was still honoured after it.
     */
    public function test_unlink_and_relink_within_one_second_invalidates_old_tokens(): void
    {
        $this->seed();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_REPLACE);

        $stale = $this->tfa->startChatReplacement('user-1', $this->lastCode());
        $this->assertInstanceOf(LinkRequest::class, $stale);

        // No clock advance anywhere in this test: same second throughout.
        $before = $this->clock->now();

        $this->tfa->unlinkAfterExternalProof('user-1', 'user asked');
        $fresh = $this->tfa->startDeepLink('user-1');
        $this->tfa->completeDeepLink($fresh->token, '555000111');

        $this->assertSame($before, $this->clock->now(), 'the whole sequence is one second');
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);

        $result = $this->tfa->completeDeepLink($stale->token, '999000444');

        $this->assertFalse($result->ok);
        $this->assertSame('555000111', $this->tfa->identity('user-1')?->chatId);
    }

    public function test_two_concurrent_ordinary_links_cannot_replace_each_other(): void
    {
        $first = $this->tfa->startDeepLink('user-1');
        $second = $this->tfa->startDeepLink('user-1');

        $inner = null;

        // The second link completes inside the first one's transition, so both
        // started from the same observed enrollment.
        $this->racingIdentities->interleaveOnTransition(function () use ($second, &$inner): void {
            $inner = $this->tfa->completeDeepLink($second->token, '777000222');
        });

        $outer = $this->tfa->completeDeepLink($first->token, '555000111');

        $this->assertNotNull($inner);
        $this->assertNotSame(
            $outer->ok,
            $inner->ok,
            'exactly one of two concurrent links may win'
        );

        // And whichever won, the stored enrollment is one of the two, not a
        // mixture: a chat that lost must not be recorded.
        $chatId = $this->tfa->identity('user-1')?->chatId;
        $this->assertContains($chatId, ['555000111', '777000222']);
        $this->assertSame($chatId, $this->tfa->identityForChat((string) $chatId)?->chatId);
    }

    /**
     * A delivery failure handler that runs late must not throw away a code the
     * user is already holding.
     */
    public function test_a_late_delivery_failure_cannot_discard_a_newer_challenge(): void
    {
        $this->seed();

        // The first send fails, but only after the cooldown has lapsed and a
        // second challenge has been issued and delivered.
        $this->telegram->failNextSend(function (): void {
            $this->clock->advance(121);
            $this->tfa->push('user-1', 'login');
        });

        $failed = $this->tfa->push('user-1', 'login');
        $this->assertFalse($failed->ok);
        $this->assertSame(ErrorCode::SendFailed, $failed->error);

        // The newer code, delivered during the failing send, must still work.
        $this->assertTrue(
            $this->tfa->verify('user-1', $this->lastCode(), 'login')->ok,
            'the cleanup for a failed send must only discard its own challenge'
        );
    }

    public function test_a_failed_unlink_transition_leaves_the_enrollment_alone(): void
    {
        $this->seed();
        $this->tfa->push('user-1', TelegramTwoFactor::PURPOSE_UNLINK);
        $code = $this->lastCode();

        // A recovery lands between the code being accepted and the unlink
        // write, so the write no longer refers to what is stored.
        $this->racingIdentities->interleaveOnTransition(function (): void {
            $this->racingIdentities->inner()->transition(
                'user-1',
                '777000222',
                IdentityStore::ANY_GENERATION,
                'gen-recovered',
            );
        });

        $this->tfa->unlink('user-1', $code);

        // Whatever the outcome reported, the stored enrollment must be the
        // recovered one rather than a half-applied mixture.
        $identity = $this->tfa->identity('user-1');
        $this->assertNotNull($identity);
        $this->assertSame('777000222', $identity->chatId);
        $this->assertSame('gen-recovered', $identity->generation);
    }

    public function test_the_generation_survives_unlinking(): void
    {
        $this->seed();

        $this->tfa->unlinkAfterExternalProof('user-1', 'user asked');

        $identity = $this->tfa->identity('user-1');

        // The row remains, carrying a new generation and no chat. This is what
        // lets revocation outlive the binding: a token minted before the unlink
        // references a generation that no longer matches, even after a relink.
        $this->assertNotNull($identity);
        $this->assertNull($identity->chatId);
        $this->assertFalse($identity->isVerified());
        $this->assertNotNull($identity->generation);
        $this->assertNotSame('gen-initial', $identity->generation);
    }
}
