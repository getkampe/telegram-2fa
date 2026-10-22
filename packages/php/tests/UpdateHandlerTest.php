<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\Webhook\UpdateHandler;

final class UpdateHandlerTest extends TestCase
{
    private UpdateHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new UpdateHandler(
            $this->tfa,
            $this->config,
            $this->store,
            $this->telegram,
            new DefaultMessages(),
        );
    }

    public function test_start_with_a_deeplink_payload_links_the_account(): void
    {
        $request = $this->tfa->startDeepLink('user-1');

        $this->handler->handle($this->message('/start ' . $request->token));

        $this->assertTrue($this->tfa->isLinked('user-1'));
        $this->assertStringContainsString('second factor', $this->telegram->lastMessage() ?? '');
    }

    public function test_start_without_a_payload_sends_the_welcome(): void
    {
        $this->handler->handle($this->message('/start'));

        $this->assertStringContainsString('security bot', $this->telegram->lastMessage() ?? '');
    }

    public function test_code_issues_a_code_for_a_linked_chat(): void
    {
        $this->linked();

        $this->handler->handle($this->message('/code'));

        $this->assertMatchesRegularExpression('/^\d{6}$/', $this->lastCode());
    }

    public function test_code_tells_an_unlinked_chat_how_to_link(): void
    {
        $this->handler->handle($this->message('/code'));

        $this->assertStringContainsString('not linked', $this->telegram->lastMessage() ?? '');
    }

    public function test_code_inside_the_cooldown_explains_the_wait(): void
    {
        $this->linked();
        $this->handler->handle($this->message('/code'));
        $this->handler->handle($this->message('/code'));

        $this->assertStringContainsString('just sent', $this->telegram->lastMessage() ?? '');
    }

    /**
     * Telegram retries an update it believes was not delivered. Without
     * deduplication a retried /code mints a second code and resets the
     * cooldown, which is both a surprise to the user and a free extra send.
     */
    public function test_a_repeated_update_id_is_dropped(): void
    {
        $this->linked();
        $update = $this->message('/code');

        $this->assertTrue($this->handler->handle($update));
        $this->assertFalse($this->handler->handle($update));
        $this->assertSame(1, $this->telegram->messageCount());
    }

    public function test_group_chats_are_ignored(): void
    {
        $this->linked('user-1', '-1001234567890');

        $update = $this->message('/code', '-1001234567890');
        $update['message']['chat']['type'] = 'supergroup';

        $this->handler->handle($update);

        // Otherwise the bot hands out verification codes in front of every
        // member of the group.
        $this->assertSame(0, $this->telegram->messageCount());
    }

    public function test_free_text_is_not_treated_as_a_code(): void
    {
        $this->linked();

        $this->handler->handle($this->message('123456'));

        $this->assertStringContainsString('do not know that command', $this->telegram->lastMessage() ?? '');
    }

    public function test_a_command_addressed_to_the_bot_by_name_is_understood(): void
    {
        $this->linked();

        $this->handler->handle($this->message('/code@kampe_test_bot'));

        $this->assertMatchesRegularExpression('/^\d{6}$/', $this->lastCode());
    }

    public function test_unlink_answers_with_instructions_and_does_not_unlink(): void
    {
        $this->linked();

        $this->handler->handle($this->message('/unlink'));

        // The question deserves an answer, not the generic menu — but the bot
        // must not perform the removal: whoever holds the phone could then
        // strip the factor with no session and no password.
        $this->assertStringContainsString(
            'cannot be done from the chat',
            $this->telegram->lastMessage() ?? ''
        );
        $this->assertTrue($this->tfa->isLinked('user-1'));
    }

    public function test_unlink_in_an_unlinked_chat_says_there_is_nothing_to_remove(): void
    {
        $this->handler->handle($this->message('/unlink'));

        $this->assertStringContainsString('not linked', $this->telegram->lastMessage() ?? '');
    }

    public function test_an_unknown_command_gets_a_reply(): void
    {
        $this->handler->handle($this->message('/nonsense'));

        $this->assertStringContainsString('do not know that command', $this->telegram->lastMessage() ?? '');
    }

    public function test_an_application_command_can_be_registered(): void
    {
        $seen = null;

        $this->handler->on('balance', function (string $chatId, string $argument) use (&$seen): void {
            $seen = [$chatId, $argument];
        });

        $this->handler->handle($this->message('/balance usd'));

        $this->assertSame(['555000111', 'usd'], $seen);
    }

    public function test_a_callback_query_is_acknowledged_then_handled(): void
    {
        $this->linked();

        $this->handler->handle([
            'update_id' => 991,
            'callback_query' => [
                'id' => 'cb-1',
                'data' => 'code',
                'message' => ['chat' => ['id' => '555000111', 'type' => 'private']],
            ],
        ]);

        $this->assertSame(['cb-1'], $this->telegram->answeredCallbacks);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $this->lastCode());
    }

    public function test_an_update_with_no_message_is_ignored(): void
    {
        $this->assertFalse($this->handler->handle(['update_id' => 1]));
        $this->assertSame(0, $this->telegram->messageCount());
    }

    /**
     * @return array<string, mixed>
     */
    private function message(string $text, string $chatId = '555000111'): array
    {
        static $id = 1000;

        return [
            'update_id' => $id++,
            'message' => [
                'message_id' => 1,
                'text' => $text,
                'chat' => ['id' => $chatId, 'type' => 'private'],
            ],
        ];
    }
}
