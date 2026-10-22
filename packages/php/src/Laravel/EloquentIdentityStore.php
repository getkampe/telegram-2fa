<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Database\QueryException;
use Illuminate\Database\Eloquent\Model;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Results\Identity;

/**
 * Stores the binding on an Eloquent model, by default your User.
 *
 * Three columns, added by the package migration:
 * telegram_chat_id, telegram_linked_at, telegram_unlinked_at.
 */
final class EloquentIdentityStore implements IdentityStore
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        private readonly string $model,
        private readonly string $chatIdColumn = 'telegram_chat_id',
        private readonly string $linkedAtColumn = 'telegram_linked_at',
    ) {
    }

    public function findByUserId(string $userId): ?Identity
    {
        $row = $this->model::query()->find($userId);

        return $row === null ? null : $this->toIdentity($row);
    }

    public function findByChatId(string $chatId): ?Identity
    {
        $row = $this->model::query()->where($this->chatIdColumn, $chatId)->first();

        return $row === null ? null : $this->toIdentity($row);
    }

    public function link(string $userId, string $chatId): Identity
    {
        $row = $this->model::query()->findOrFail($userId);

        $row->setAttribute($this->chatIdColumn, $chatId);
        $row->setAttribute($this->linkedAtColumn, now());

        try {
            $row->save();
        } catch (QueryException $e) {
            // The unique index on telegram_chat_id is what actually guarantees
            // one chat per account. The application-level check in the core
            // runs first, but two concurrent links of the same chat both pass
            // it and only one can pass this.
            if ($this->isUniqueViolation($e)) {
                throw new ChatAlreadyLinked(
                    'That Telegram chat is already the second factor for another account.',
                    0,
                    $e
                );
            }

            throw $e;
        }

        return $this->toIdentity($row);
    }

    public function unlink(string $userId): void
    {
        $row = $this->model::query()->find($userId);

        if ($row === null) {
            return;
        }

        $row->setAttribute($this->chatIdColumn, null);
        $row->setAttribute($this->linkedAtColumn, null);
        $row->save();
    }

    private function toIdentity(Model $row): ?Identity
    {
        $chatId = $row->getAttribute($this->chatIdColumn);

        if ($chatId === null || $chatId === '') {
            return null;
        }

        $linkedAt = $row->getAttribute($this->linkedAtColumn);

        return new Identity(
            (string) $row->getKey(),
            (string) $chatId,
            $linkedAt === null ? null : (int) strtotime((string) $linkedAt),
        );
    }

    private function isUniqueViolation(QueryException $e): bool
    {
        // 23000 and 23505 are the SQLSTATE classes for integrity constraint
        // violations in MySQL/SQLite and PostgreSQL respectively.
        return in_array((string) $e->getCode(), ['23000', '23505'], true);
    }
}
