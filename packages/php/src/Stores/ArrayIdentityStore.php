<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Stores;

use Kampe\TelegramTwoFactor\Contracts\Clock;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Results\Identity;
use Kampe\TelegramTwoFactor\Support\SystemClock;

/**
 * An in-memory identity store, for tests and for sketching an integration
 * before wiring it to a database.
 *
 * It models both rules a real store must enforce: one chat belongs to one
 * account, and a transition only applies when the stored generation is the one
 * the caller expected. Rows survive unlinking, because the generation has to.
 */
final class ArrayIdentityStore implements IdentityStore
{
    /** @var array<string, Identity> keyed by user id */
    private array $rows = [];

    private readonly Clock $clock;

    public function __construct(?Clock $clock = null)
    {
        $this->clock = $clock ?? new SystemClock();
    }

    public function findByUserId(string $userId): ?Identity
    {
        return $this->rows[$userId] ?? null;
    }

    public function findByChatId(string $chatId): ?Identity
    {
        foreach ($this->rows as $identity) {
            if ($identity->chatId !== null && $identity->chatId === $chatId) {
                return $identity;
            }
        }

        return null;
    }

    public function transition(
        string $userId,
        ?string $chatId,
        ?string $expected,
        string $next,
    ): ?Identity {
        $current = $this->rows[$userId] ?? null;

        if ($expected !== self::ANY_GENERATION && ($current?->generation ?? null) !== $expected) {
            // The expectation failed, so the stored row is left exactly as it
            // was. Returning null rather than throwing lets the caller decide
            // whether this is a conflict or a stale token.
            return null;
        }

        if ($chatId !== null) {
            $holder = $this->findByChatId($chatId);

            if ($holder !== null && $holder->userId !== $userId) {
                throw new ChatAlreadyLinked(
                    'That Telegram chat is already the second factor for another account.'
                );
            }
        }

        $identity = new Identity(
            $userId,
            $chatId,
            $chatId === null ? null : $this->clock->now(),
            $next,
        );

        $this->rows[$userId] = $identity;

        return $identity;
    }

    /**
     * Test helper: seed a verified enrollment without going through a flow.
     */
    public function seed(string $userId, string $chatId, string $generation): Identity
    {
        $identity = new Identity($userId, $chatId, $this->clock->now(), $generation);
        $this->rows[$userId] = $identity;

        return $identity;
    }
}
