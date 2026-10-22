<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Laravel;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Database\QueryException;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Results\Identity;

/**
 * Stores the enrollment on an Eloquent model, by default your User.
 *
 * Four columns, added by the package migration: telegram_chat_id,
 * telegram_linked_at, telegram_enrollment, and a unique index on the chat id.
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
        private readonly string $generationColumn = 'telegram_enrollment',
    ) {
    }

    public function findByUserId(string $userId): ?Identity
    {
        $row = $this->model::query()->find($userId);

        return $row === null ? null : $this->toIdentity($row);
    }

    public function findByChatId(string $chatId): ?Identity
    {
        $row = $this->model::query()
            ->whereNotNull($this->chatIdColumn)
            ->where($this->chatIdColumn, $chatId)
            ->first();

        return $row === null ? null : $this->toIdentity($row);
    }

    public function transition(
        string $userId,
        ?string $chatId,
        ?string $expected,
        string $next,
    ): ?Identity {
        $query = $this->model::query()->whereKey($userId);

        // The comparison lives in the WHERE clause, so the database decides
        // whether this transition applies. Reading the generation in PHP and
        // then writing would leave a window in which a recovery could land and
        // be silently overwritten.
        if ($expected !== self::ANY_GENERATION) {
            $query->where(function ($q) use ($expected): void {
                $expected === null
                    ? $q->whereNull($this->generationColumn)
                    : $q->where($this->generationColumn, $expected);
            });
        }

        try {
            $affected = $query->update([
                $this->chatIdColumn => $chatId,
                // Carbon::now(), not the global now() helper: that helper only
                // exists once illuminate/support's helpers file has been
                // autoloaded, which a full framework boot does and a package
                // consumed outside one does not. Calling it made this a fatal
                // error rather than a write.
                $this->linkedAtColumn => $chatId === null ? null : Carbon::now(),
                $this->generationColumn => $next,
            ]);
        } catch (QueryException $e) {
            // The unique index on the chat id column is what actually
            // guarantees one chat per account. The application-level check runs
            // first, but two concurrent transitions onto one chat both pass it
            // and only one can pass the index.
            if ($this->isUniqueViolation($e)) {
                throw new ChatAlreadyLinked(
                    'That Telegram chat is already the second factor for another account.',
                    0,
                    $e
                );
            }

            throw $e;
        }

        if ($affected !== 1) {
            // Either the row is gone or its generation is not what the caller
            // expected. Nothing was written.
            return null;
        }

        return $this->findByUserId($userId);
    }

    private function toIdentity(Model $row): Identity
    {
        $chatId = $row->getAttribute($this->chatIdColumn);
        $linkedAt = $row->getAttribute($this->linkedAtColumn);
        $generation = $row->getAttribute($this->generationColumn);

        return new Identity(
            (string) $row->getKey(),
            $chatId === null || $chatId === '' ? null : (string) $chatId,
            $linkedAt === null ? null : (int) strtotime((string) $linkedAt),
            $generation === null || $generation === '' ? null : (string) $generation,
        );
    }

    private function isUniqueViolation(QueryException $e): bool
    {
        // 23000 and 23505 are the SQLSTATE classes for integrity constraint
        // violations in MySQL/SQLite and PostgreSQL respectively.
        return in_array((string) $e->getCode(), ['23000', '23505'], true);
    }
}
