<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Contracts\Clock;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Results\Identity;
use Kampe\TelegramTwoFactor\Support\SystemClock;

/**
 * An in-memory identity store, for tests and for working out an integration
 * before wiring it to a database.
 *
 * It models the uniqueness rule a real store must enforce with a constraint:
 * one chat belongs to one user, and a second claim on it is refused rather than
 * allowed to overwrite the first.
 */
final class ArrayIdentityStore implements IdentityStore
{
    /** @var array<string, Identity> keyed by user id */
    private array $byUser = [];

    private readonly Clock $clock;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    public function findByUserId(string $userId): ?Identity
    {
        return $this->byUser[$userId] ?? null;
    }

    public function findByChatId(string $chatId): ?Identity
    {
        foreach ($this->byUser as $identity) {
            if ($identity->chatId === $chatId) {
                return $identity;
            }
        }

        return null;
    }

    public function link(string $userId, string $chatId): Identity
    {
        $holder = $this->findByChatId($chatId);

        if ($holder !== null && $holder->userId !== $userId) {
            throw new ChatAlreadyLinked(
                'That Telegram chat is already the second factor for another account.'
            );
        }

        $identity = new Identity($userId, $chatId, $this->clock->now());
        $this->byUser[$userId] = $identity;

        return $identity;
    }

    public function unlink(string $userId): void
    {
        unset($this->byUser[$userId]);
    }
}
