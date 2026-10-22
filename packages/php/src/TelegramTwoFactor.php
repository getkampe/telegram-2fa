<?php

declare(strict_types=1);

namespace Kampe\TelegramTwoFactor;

use Kampe\TelegramTwoFactor\Codes\CodeGenerator;
use Kampe\TelegramTwoFactor\Codes\CodeHasher;
use Kampe\TelegramTwoFactor\Contracts\Clock;
use Kampe\TelegramTwoFactor\Contracts\CodeStore;
use Kampe\TelegramTwoFactor\Contracts\IdentityStore;
use Kampe\TelegramTwoFactor\Contracts\Logger;
use Kampe\TelegramTwoFactor\Contracts\Messages;
use Kampe\TelegramTwoFactor\Contracts\TelegramClient;
use Kampe\TelegramTwoFactor\Exceptions\ChatAlreadyLinked;
use Kampe\TelegramTwoFactor\Results\ChallengeResult;
use Kampe\TelegramTwoFactor\Results\Identity;
use Kampe\TelegramTwoFactor\Results\LinkRequest;
use Kampe\TelegramTwoFactor\Results\LinkResult;
use Kampe\TelegramTwoFactor\Results\VerificationResult;
use Kampe\TelegramTwoFactor\Support\NullLogger;
use Kampe\TelegramTwoFactor\Support\SystemClock;

/**
 * Telegram as a second authentication factor.
 *
 * The whole protocol, with no framework underneath it: linking (two flows),
 * challenge (two directions), verification, unlinking. Everything it touches
 * arrives through a contract, so the same class runs on Laravel's cache and
 * Eloquent, on Redis and PDO, or on arrays in a test.
 *
 * @see SPEC.md for the normative protocol this implements.
 */
final class TelegramTwoFactor
{
    /** The default purpose, for an ordinary sign-in. */
    public const PURPOSE_LOGIN = 'login';

    /**
     * The purpose of a code the user fetched themselves with /code.
     *
     * Such a code carries no knowledge of what it is about to authorise, so it
     * satisfies any requested purpose. That is sound because the user asked for
     * it deliberately — nothing the application did caused it to exist.
     */
    public const PURPOSE_ON_DEMAND = 'on_demand';

    /** Proving the current factor before rebinding to a new chat. */
    public const PURPOSE_REPLACE = 'replace';

    /** Proving the current factor before removing it. */
    public const PURPOSE_UNLINK = 'unlink';

    private readonly CodeGenerator $codes;

    private readonly CodeHasher $hasher;

    private readonly Clock $clock;

    private readonly Logger $logger;

    public function __construct(
        private readonly Config $config,
        private readonly CodeStore $store,
        private readonly IdentityStore $identities,
        private readonly TelegramClient $telegram,
        private readonly Messages $messages,
        ?Clock $clock = null,
        ?Logger $logger = null,
        ?CodeGenerator $codes = null,
        ?CodeHasher $hasher = null,
    ) {
        $this->clock = $clock ?? new SystemClock();
        $this->logger = $logger ?? new NullLogger();
        $this->codes = $codes ?? new CodeGenerator();
        $this->hasher = $hasher ?? new CodeHasher(
            $this->config->hashAlgorithm,
            $this->config->hashPepper,
        );
    }

    public function config(): Config
    {
        return $this->config;
    }

    // ---------------------------------------------------------------- identity

    /**
     * Whether this account has a proven Telegram second factor.
     */
    public function isLinked(string $userId): bool
    {
        return $this->identities->findByUserId($userId)?->isVerified() ?? false;
    }

    public function identity(string $userId): ?Identity
    {
        return $this->identities->findByUserId($userId);
    }

    /**
     * The identity behind a Telegram chat, for the webhook side of the protocol.
     */
    public function identityForChat(string $chatId): ?Identity
    {
        return $this->identities->findByChatId($chatId);
    }

    // ----------------------------------------------------------------- linking

    /**
     * Begin the deeplink flow: mint a nonce bound to this account.
     *
     * Hand the returned url to the user as a button, or as a QR code when they
     * are on a desktop and Telegram is on their phone. The token is bound to the
     * account before it ever reaches Telegram, which is what makes this flow
     * preferable to the paste flow: there is no window in which a token is valid
     * for whoever happens to present it.
     *
     * Minting is harmless for an already-linked account, so this does not check;
     * the check happens in completeDeepLink, where acting on it matters.
     */
    public function startDeepLink(string $userId): LinkRequest
    {
        $token = $this->codes->deepLinkToken();
        $expiresAt = $this->clock->now() + $this->config->linkTtl;

        $this->store->put(
            $this->config->key('link', $this->hasher->hash($token)),
            ['user_id' => $userId, 'expires_at' => $expiresAt],
            $this->config->linkTtl,
        );

        $this->logger->info('telegram-2fa: deeplink issued', ['user_id' => $userId]);

        return new LinkRequest($token, $expiresAt, $this->config->deepLinkUrl($token));
    }

    /**
     * Finish the deeplink flow, from the /start payload in a webhook update.
     */
    public function completeDeepLink(string $token, string $chatId): LinkResult
    {
        $key = $this->config->key('link', $this->hasher->hash($token));
        $record = $this->store->get($key);

        if (! is_array($record) || ! isset($record['user_id'])) {
            $this->logger->warning('telegram-2fa: deeplink token not resolvable', ['chat_id' => $chatId]);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        if (($record['expires_at'] ?? 0) < $this->clock->now()) {
            $this->store->forget($key);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        // Single use, and burned before the link is attempted rather than after:
        // a token that survives a failed attempt can be retried by anyone who
        // saw it, and a token that survives a successful one can be replayed.
        $this->store->forget($key);

        return $this->bind(
            (string) $record['user_id'],
            $chatId,
            replace: ($record['replace'] ?? false) === true,
        );
    }

    /**
     * Begin moving the factor to a different Telegram account.
     *
     * Linking never silently moves a verified binding, because a flow that did
     * would let anyone holding a session attach their own chat to the account.
     * So replacement is explicit and costs a code from the chat being replaced:
     * prove the current factor here, then resolve the returned token from the
     * new chat.
     *
     * A user who has lost the old chat entirely cannot do this, and belongs in
     * unlinkAfterExternalProof() instead.
     *
     * @return LinkRequest|VerificationResult The request on success, or the
     *         verification failure that stopped it.
     */
    public function startChatReplacement(string $userId, string $code): LinkRequest|VerificationResult
    {
        $identity = $this->identities->findByUserId($userId);

        if ($identity === null || ! $identity->isVerified()) {
            return VerificationResult::fail(ErrorCode::NotLinked);
        }

        $proof = $this->verify($userId, $code, self::PURPOSE_REPLACE);

        if (! $proof->ok) {
            return $proof;
        }

        $token = $this->codes->deepLinkToken();
        $expiresAt = $this->clock->now() + $this->config->linkTtl;

        // The replace mark lives on the stored token, not on the call that
        // resolves it. Taking it from the resolution side would make the proof
        // above skippable by presenting an ordinary token.
        $this->store->put(
            $this->config->key('link', $this->hasher->hash($token)),
            ['user_id' => $userId, 'expires_at' => $expiresAt, 'replace' => true],
            $this->config->linkTtl,
        );

        $this->logger->info('telegram-2fa: chat replacement authorised', ['user_id' => $userId]);

        return new LinkRequest($token, $expiresAt, $this->config->deepLinkUrl($token));
    }

    /**
     * Begin the paste flow, from the bot side: mint a code bound to this chat.
     */
    public function startPasteLink(string $chatId): LinkRequest
    {
        $code = $this->codes->linkCode($this->config->linkCodeLength);
        $expiresAt = $this->clock->now() + $this->config->linkTtl;

        $this->store->put(
            $this->config->key('link', $this->hasher->hash($code)),
            ['chat_id' => $chatId, 'expires_at' => $expiresAt],
            $this->config->linkTtl,
        );

        $this->logger->info('telegram-2fa: paste link code issued');

        return new LinkRequest($code, $expiresAt);
    }

    /**
     * Finish the paste flow, from an authenticated page in your application.
     *
     * The caller is responsible for two things this method cannot check: that
     * $userId comes from the session rather than the request body, and that the
     * endpoint is rate-limited. Without the rate limit, the attempt budget on
     * this flow is unbounded, and the link code namespace is shared across all
     * users.
     */
    public function completePasteLink(string $userId, string $code): LinkResult
    {
        $normalised = strtoupper(trim($code));
        $key = $this->config->key('link', $this->hasher->hash($normalised));
        $record = $this->store->get($key);

        if (! is_array($record) || ! isset($record['chat_id'])) {
            $this->logger->warning('telegram-2fa: paste code not resolvable', ['user_id' => $userId]);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        if (($record['expires_at'] ?? 0) < $this->clock->now()) {
            $this->store->forget($key);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        $this->store->forget($key);

        return $this->bind($userId, (string) $record['chat_id']);
    }

    /**
     * Record the binding, refusing anything that would create a shared factor.
     *
     * @param  bool  $replace  Whether the token carried the replace mark of
     *                         startChatReplacement(), which is the only thing
     *                         that authorises moving a verified binding.
     */
    private function bind(string $userId, string $chatId, bool $replace = false): LinkResult
    {
        $existingForUser = $this->identities->findByUserId($userId);

        if ($existingForUser !== null && $existingForUser->isVerified()) {
            // Re-presenting the same chat is a double submit, not a conflict.
            if ($existingForUser->chatId === $chatId) {
                return LinkResult::linked($existingForUser);
            }

            if (! $replace) {
                return LinkResult::failed(ErrorCode::AlreadyLinked);
            }

            // Authorised replacement: release the old chat first so the new one
            // can take the unique slot, and tell the old chat it is done. If
            // the user did not request this, that message is how they find out.
            $this->telegram->sendMessage(
                $existingForUser->chatId,
                $this->messages->unlinked($this->config->appName),
            );

            $this->identities->unlink($userId);
        }

        $existingForChat = $this->identities->findByChatId($chatId);

        if ($existingForChat !== null && $existingForChat->userId !== $userId) {
            $this->logger->warning('telegram-2fa: chat already linked to another account', [
                'user_id' => $userId,
            ]);

            return LinkResult::failed(ErrorCode::AlreadyLinked);
        }

        try {
            $identity = $this->identities->link($userId, $chatId);
        } catch (ChatAlreadyLinked) {
            // The store's uniqueness constraint caught what the checks above
            // raced past. Two simultaneous links of one chat land here.
            return LinkResult::failed(ErrorCode::AlreadyLinked);
        }

        $this->logger->info('telegram-2fa: linked', ['user_id' => $userId]);

        return LinkResult::linked($identity);
    }

    // --------------------------------------------------------------- challenge

    /**
     * Push direction: issue a code and send it to the linked chat.
     *
     * The code is not in the return value. It is generated, hashed into the
     * store, handed to Telegram, and dropped — so the result can go straight
     * into an HTTP response.
     *
     * @param  string  $purpose  Recorded with the code and surfaced on
     *                           verification, so a code issued for one step
     *                           cannot be reported as proof of another.
     */
    public function push(string $userId, string $purpose = self::PURPOSE_LOGIN): ChallengeResult
    {
        $identity = $this->identities->findByUserId($userId);

        if ($identity === null || ! $identity->isVerified()) {
            return ChallengeResult::failed(ErrorCode::NotLinked);
        }

        if (($blocked = $this->cooldownRemaining($userId)) !== null) {
            return ChallengeResult::failed(ErrorCode::Cooldown, $blocked);
        }

        $code = $this->issue($userId, $purpose);

        $sent = $this->telegram->sendMessage(
            $identity->chatId,
            $this->messages->code($code, $this->config->codeTtl),
        );

        if (! $sent) {
            // Drop the code rather than leaving one live that the user never
            // received: otherwise the account sits in a state where the only
            // way forward is to wait out the cooldown.
            $this->store->forget($this->config->key('code', $userId));
            $this->store->forget($this->config->key('cooldown', $userId));

            $this->logger->error('telegram-2fa: delivery failed', ['user_id' => $userId]);

            return ChallengeResult::failed(ErrorCode::SendFailed);
        }

        $this->logger->info('telegram-2fa: code sent', [
            'user_id' => $userId,
            'purpose' => $purpose,
        ]);

        return ChallengeResult::sent(
            $this->clock->now() + $this->config->codeTtl,
            $this->clock->now() + $this->config->cooldown,
        );
    }

    /**
     * Pull direction: the user asked the bot for a code.
     *
     * Called from the webhook when a linked chat sends /code. Writes the same
     * store key as push, so one verification call accepts a code from either
     * direction — see the single-key rule in SPEC.md section 4.
     */
    public function pull(string $chatId, string $purpose = self::PURPOSE_ON_DEMAND): ChallengeResult
    {
        $identity = $this->identities->findByChatId($chatId);

        if ($identity === null || ! $identity->isVerified()) {
            return ChallengeResult::failed(ErrorCode::NotLinked);
        }

        if (($blocked = $this->cooldownRemaining($identity->userId)) !== null) {
            return ChallengeResult::failed(ErrorCode::Cooldown, $blocked);
        }

        $code = $this->issue($identity->userId, $purpose);

        $sent = $this->telegram->sendMessage(
            $chatId,
            $this->messages->code($code, $this->config->codeTtl),
        );

        if (! $sent) {
            $this->store->forget($this->config->key('code', $identity->userId));
            $this->store->forget($this->config->key('cooldown', $identity->userId));

            return ChallengeResult::failed(ErrorCode::SendFailed);
        }

        $this->logger->info('telegram-2fa: code issued on demand', [
            'user_id' => $identity->userId,
        ]);

        return ChallengeResult::sent(
            $this->clock->now() + $this->config->codeTtl,
            $this->clock->now() + $this->config->cooldown,
        );
    }

    /**
     * Generate a code, store its hash, and arm the cooldown.
     *
     * Returns the plaintext to exactly one caller, which sends it and discards
     * it. Nothing else in the library sees it.
     */
    private function issue(string $userId, string $purpose): string
    {
        $code = $this->codes->twoFactorCode($this->config->codeLength);
        $now = $this->clock->now();
        $expiresAt = $now + $this->config->codeTtl;

        $this->store->put(
            $this->config->key('code', $userId),
            [
                'hash' => $this->hasher->hash($code),
                'expires_at' => $expiresAt,
                'attempts' => 0,
                'purpose' => $purpose,
            ],
            $this->config->codeTtl,
        );

        $this->store->put(
            $this->config->key('cooldown', $userId),
            $now + $this->config->cooldown,
            $this->config->cooldown,
        );

        return $code;
    }

    /**
     * The timestamp at which another send is allowed, or null if one is allowed now.
     */
    private function cooldownRemaining(string $userId): ?int
    {
        $nextSendAt = $this->store->get($this->config->key('cooldown', $userId));

        if (! is_int($nextSendAt) && ! is_numeric($nextSendAt)) {
            return null;
        }

        $nextSendAt = (int) $nextSendAt;

        return $nextSendAt > $this->clock->now() ? $nextSendAt : null;
    }

    // ------------------------------------------------------------ verification

    /**
     * Check a submitted code.
     *
     * Single use on success, attempt-budgeted on failure, constant-time
     * throughout.
     *
     * $purpose must match what the code was issued for, and defaults to
     * PURPOSE_LOGIN exactly as push() does. There is deliberately no way to
     * skip the check: a default of "compare against nothing" would mean the
     * binding does nothing unless every call site opts in, and the call site
     * that forgets is both invisible and the one that matters — a code issued
     * to confirm a sign-in approving a payout.
     */
    public function verify(
        string $userId,
        string $code,
        string $purpose = self::PURPOSE_LOGIN,
    ): VerificationResult {
        $key = $this->config->key('code', $userId);
        $record = $this->store->get($key);

        if (! is_array($record) || ! isset($record['hash'])) {
            return VerificationResult::fail(ErrorCode::Expired);
        }

        $attempts = (int) ($record['attempts'] ?? 0);

        if ($attempts >= $this->config->maxAttempts) {
            $this->store->forget($key);

            return VerificationResult::fail(ErrorCode::TooManyAttempts, 0);
        }

        if ((int) ($record['expires_at'] ?? 0) < $this->clock->now()) {
            $this->store->forget($key);

            return VerificationResult::fail(ErrorCode::Expired);
        }

        if (! $this->purposeSatisfied((string) ($record['purpose'] ?? ''), $purpose)) {
            // A code minted to confirm a login should not also confirm a
            // withdrawal. Count it as an attempt rather than a free retry, and
            // report it as `invalid`: telling the caller that a live code
            // exists for some other purpose is information it has not proved
            // it should have.
            return $this->recordFailedAttempt($key, $record, $attempts);
        }

        if (! $this->hasher->matches((string) $record['hash'], trim($code))) {
            return $this->recordFailedAttempt($key, $record, $attempts);
        }

        $this->store->forget($key);

        $this->logger->info('telegram-2fa: verified', [
            'user_id' => $userId,
            'purpose' => $record['purpose'] ?? null,
        ]);

        return VerificationResult::pass();
    }

    /**
     * Whether a stored code may be used for the purpose being requested.
     */
    private function purposeSatisfied(string $stored, string $requested): bool
    {
        return $stored === $requested || $stored === self::PURPOSE_ON_DEMAND;
    }

    /**
     * @param  array<string, mixed>  $record
     */
    private function recordFailedAttempt(string $key, array $record, int $attempts): VerificationResult
    {
        $attempts++;
        $remaining = $this->config->maxAttempts - $attempts;

        if ($remaining <= 0) {
            $this->store->forget($key);

            return VerificationResult::fail(ErrorCode::TooManyAttempts, 0);
        }

        $record['attempts'] = $attempts;

        // Re-store under the code's own remaining lifetime. Writing it back with
        // a fresh full TTL would let an attacker extend a code indefinitely by
        // guessing wrong, which turns the attempt budget into the only limit and
        // removes the time limit entirely.
        $this->store->put(
            $key,
            $record,
            max(1, (int) $record['expires_at'] - $this->clock->now()),
        );

        return VerificationResult::fail(ErrorCode::Invalid, $remaining);
    }

    // --------------------------------------------------------------- unlinking

    /**
     * Remove the factor, proving possession of it first.
     *
     * Unlinking is the step an attacker with a stolen session but no phone
     * needs, so it demands the same proof as any other protected action.
     */
    public function unlink(string $userId, string $code): VerificationResult
    {
        $identity = $this->identities->findByUserId($userId);

        if ($identity === null || ! $identity->isVerified()) {
            return VerificationResult::fail(ErrorCode::NotLinked);
        }

        // Under PURPOSE_UNLINK, so that a code pushed for a login cannot remove
        // the factor. A code the user fetched with /code still works, because
        // on-demand codes are general-purpose.
        $result = $this->verify($userId, $code, self::PURPOSE_UNLINK);

        if (! $result->ok) {
            return $result;
        }

        $this->detach($identity);

        return VerificationResult::pass();
    }

    /**
     * Remove the factor when another factor has already proved the request.
     *
     * For recovery paths: the user still has their authenticator, or passed an
     * out-of-band identity check, but has lost the Telegram account. The caller
     * takes responsibility for that proof — this method performs none.
     */
    public function unlinkAfterExternalProof(string $userId, string $reason): bool
    {
        $identity = $this->identities->findByUserId($userId);

        if ($identity === null) {
            return false;
        }

        $this->detach($identity);

        $this->logger->warning('telegram-2fa: unlinked via external proof', [
            'user_id' => $userId,
            'reason' => $reason,
        ]);

        return true;
    }

    private function detach(Identity $identity): void
    {
        $this->identities->unlink($identity->userId);

        $this->store->forget($this->config->key('code', $identity->userId));
        $this->store->forget($this->config->key('cooldown', $identity->userId));

        // Best effort: the user should hear that their factor was removed even
        // if, especially if, they did not do it themselves.
        $this->telegram->sendMessage(
            $identity->chatId,
            $this->messages->unlinked($this->config->appName),
        );

        $this->logger->info('telegram-2fa: unlinked', ['user_id' => $identity->userId]);
    }
}
