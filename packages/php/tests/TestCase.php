<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Tests;

use Kampe\TelegramTwoFactor\Config;
use Kampe\TelegramTwoFactor\Stores\ArrayCodeStore;
use Kampe\TelegramTwoFactor\Stores\ArrayIdentityStore;
use Kampe\TelegramTwoFactor\Support\FrozenClock;
use Kampe\TelegramTwoFactor\Telegram\DefaultMessages;
use Kampe\TelegramTwoFactor\TelegramTwoFactor;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected FrozenClock $clock;

    protected ArrayCodeStore $store;

    protected ArrayIdentityStore $identities;

    protected FakeTelegramClient $telegram;

    protected Config $config;

    protected TelegramTwoFactor $tfa;

    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FrozenClock();
        $this->store = new ArrayCodeStore($this->clock);
        $this->identities = new ArrayIdentityStore($this->clock);
        $this->telegram = new FakeTelegramClient();
        $this->config = $this->config();

        $this->tfa = new TelegramTwoFactor(
            $this->config,
            $this->store,
            $this->identities,
            $this->telegram,
            new DefaultMessages(),
            $this->clock,
        );
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    protected function config(array $overrides = []): Config
    {
        return Config::fromArray(array_merge([
            'bot_token' => '123456789:AAFakeTokenForTestsOnly_0123456789abc',
            'webhook_secret' => str_repeat('s', 48),
            'bot_username' => 'kampe_test_bot',
            'app_name' => 'Kampe',
        ], $overrides));
    }

    /**
     * Link a user to a chat without going through either link flow.
     */
    protected function linked(string $userId = 'user-1', string $chatId = '555000111'): void
    {
        $this->identities->link($userId, $chatId);
    }

    /**
     * The code from the most recent message the fake client was asked to send.
     *
     * Tests have to recover the code from the outgoing message because the
     * library deliberately never returns it.
     */
    protected function lastCode(): string
    {
        preg_match('/<code>([^<]+)<\/code>/', $this->telegram->lastMessage() ?? '', $m);

        return $m[1] ?? '';
    }
}
