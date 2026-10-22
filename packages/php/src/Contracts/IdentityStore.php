<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor\Contracts;

use Kampe\TelegramTwoFactor\Results\Identity;

/**
 * Durable storage of the enrollment: which chat is an account's second factor,
 * and which generation of that enrollment is current.
 *
 * Usually four columns on your users table. Two rules the implementation, not
 * the caller, has to guarantee:
 *
 * 1. **Chat uniqueness, at the storage layer.** A chat id maps to at most one
 *    account, enforced by a unique index rather than only an application check
 *    — two concurrent links both pass a check and only one can pass an index.
 *    Without it, one Telegram account becomes the second factor for many
 *    accounts, so one compromised Telegram account compromises all of them.
 *
 * 2. **Transitions are conditional.** Every change of state goes through
 *    transition(), which must compare the stored generation and write in one
 *    operation. Read-then-write cannot express this: a recovery landing between
 *    a caller's validation and its write would be silently overwritten, which
 *    is exactly how a replacement token outlived the enrollment it proved.
 */
interface IdentityStore
{
    /**
     * Expectation value meaning "whatever is there now".
     *
     * For recovery paths, where the caller has already proved identity by other
     * means and must not be blocked by a concurrent change.
     */
    public const ANY_GENERATION = "\0any";

    /**
     * The enrollment for an account, or null when the account has no row.
     *
     * May return an unlinked or unverified enrollment; callers decide what is
     * acceptable. The generation must be returned even when no chat is linked.
     */
    public function findByUserId(string $userId): ?Identity;

    /**
     * The enrollment for a Telegram chat, or null when the chat is not known.
     *
     * Must never match an account whose chat id is null.
     */
    public function findByChatId(string $chatId): ?Identity;

    /**
     * Move an account to a new enrollment state, if it is in the expected one.
     *
     * The whole point is that the comparison and the write are one operation.
     *
     * @param  string|null  $chatId    The chat to bind, or null to unlink.
     * @param  string|null  $expected  The generation the caller believes is
     *                                 current; null means "no generation
     *                                 recorded yet"; ANY_GENERATION skips the
     *                                 check.
     * @param  string  $next           The generation to store. Callers always
     *                                 supply a fresh one, including when
     *                                 unlinking, so that authority over the old
     *                                 enrollment dies even though no chat
     *                                 remains.
     * @return Identity|null The new state, or null when the expectation did not
     *                       hold — in which case the stored row must be left
     *                       exactly as it was.
     *
     * @throws \Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked When the
     *         chat belongs to another account.
     */
    public function transition(
        string $userId,
        ?string $chatId,
        ?string $expected,
        string $next,
    ): ?Identity;
}
