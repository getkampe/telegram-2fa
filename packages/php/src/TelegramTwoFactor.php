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
        // Single use, and taken atomically: a token read now and deleted later
        // can be resolved twice by two concurrent /start messages, and a token
        // that survives a failed attempt can be retried by anyone who saw it —
        // and it travelled through a chat, so others may have.
        $record = $this->store->take($this->config->key('link', $this->hasher->hash($token)));

        if (! is_array($record) || ! isset($record['user_id'])) {
            $this->logger->warning('telegram-2fa: deeplink token not resolvable', ['chat_id' => $chatId]);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        if (($record['expires_at'] ?? 0) < $this->clock->now()) {
            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        $replace = ($record['replace'] ?? false) === true;

        // A replacement token carries authority over an existing factor, so it
        // is only valid against the binding whose possession was proved. If
        // that binding has since changed — recovered through support, unlinked,
        // or already replaced — the proof no longer refers to anything and the
        // token is void. Without this, a token minted before an account
        // recovery still moves the factor afterwards, which hands whoever holds
        // it the new chat as well.
        $provenGeneration = is_string($record['generation'] ?? null) ? $record['generation'] : null;

        if ($replace && ! $this->generationIsCurrent((string) $record['user_id'], $provenGeneration)) {
            $this->logger->warning('telegram-2fa: stale replacement token rejected', [
                'user_id' => $record['user_id'],
            ]);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        return $this->bind(
            (string) $record['user_id'],
            $chatId,
            replace: $replace,
            provenGeneration: $provenGeneration,
        );
    }

    /**
     * Whether the enrollment a replacement token was issued against is current.
     *
     * The token records the generation it proved. Any transition since —
     * recovery, unlinking, another replacement — has changed it, so the proof
     * refers to an enrollment that no longer exists.
     *
     * This check is advisory: it gives a clear error early. The binding write
     * repeats it as a condition, which is what actually makes it safe, because
     * a recovery can land between this read and that write.
     */
    private function generationIsCurrent(string $userId, mixed $generation): bool
    {
        if (! is_string($generation) || $generation === '') {
            return false;
        }

        $identity = $this->identities->findByUserId($userId);

        if ($identity === null || ! $identity->isVerified() || $identity->generation === null) {
            return false;
        }

        return hash_equals($identity->generation, $generation);
    }

    /**
     * A fresh enrollment generation.
     *
     * Random rather than a counter: nothing needs ordering, only inequality,
     * and a random value cannot be predicted from the ones before it.
     */
    private function nextGeneration(): string
    {
        return bin2hex(random_bytes(16));
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

        // Captured *before* verifying, because this is the enrollment the user
        // is about to prove possession of. It is what the token must record.
        $proven = $identity->generation;

        $proof = $this->verify($userId, $code, self::PURPOSE_REPLACE);

        if (! $proof->ok) {
            return $proof;
        }

        if ($proven === null) {
            // A row enrolled before the generation column existed. Assign one,
            // conditional on it still being absent — which doubles as the check
            // below: if anything changed the enrollment while the code was being
            // verified, the generation is no longer null and this declines.
            $assigned = $this->identities->transition(
                $userId,
                $identity->chatId,
                null,
                $this->nextGeneration(),
            );

            if ($assigned === null || ! $assigned->isVerified() || $assigned->generation === null) {
                return VerificationResult::fail(ErrorCode::Expired);
            }

            return $this->mintReplacementToken($userId, $assigned->generation);
        }

        // Confirm the enrollment did not move while the code was being
        // verified, and reject if it did. What must never happen is adopting
        // the generation read *after* verification: a recovery landing in that
        // window would have its own new generation, and recording that would
        // hand this token authority over an enrollment the user never proved —
        // the recovered one.
        $after = $this->identities->findByUserId($userId);

        if ($after === null || ! $after->isVerified() || ! hash_equals((string) $after->generation, $proven)) {
            $this->logger->warning(
                'telegram-2fa: enrollment changed during replacement authorisation',
                ['user_id' => $userId],
            );

            return VerificationResult::fail(ErrorCode::Expired);
        }

        return $this->mintReplacementToken($userId, $proven);
    }

    /**
     * Store a replacement token against exactly one enrollment generation.
     *
     * Separate so there is a single place the generation is written, and so no
     * caller can pass one it read later than the proof.
     */
    private function mintReplacementToken(string $userId, string $provenGeneration): LinkRequest
    {
        $token = $this->codes->deepLinkToken();
        $expiresAt = $this->clock->now() + $this->config->linkTtl;

        // The replace mark lives on the stored token, not on the call that
        // resolves it. Taking it from the resolution side would make the proof
        // skippable by presenting an ordinary token.
        //
        // The generation pins the authority to the enrollment proved. The
        // binding write repeats this as its CAS expectation, so a recovery
        // landing between here and there makes that write fail rather than
        // overwrite the recovered enrollment.
        $this->store->put(
            $this->config->key('link', $this->hasher->hash($token)),
            [
                'user_id' => $userId,
                'expires_at' => $expiresAt,
                'replace' => true,
                'generation' => $provenGeneration,
            ],
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
        $record = $this->store->take($this->config->key('link', $this->hasher->hash($normalised)));

        if (! is_array($record) || ! isset($record['chat_id'])) {
            $this->logger->warning('telegram-2fa: paste code not resolvable', ['user_id' => $userId]);

            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        if (($record['expires_at'] ?? 0) < $this->clock->now()) {
            return LinkResult::failed(ErrorCode::InvalidToken);
        }

        return $this->bind($userId, (string) $record['chat_id']);
    }

    /**
     * Record the enrollment, as one conditional transition.
     *
     * Everything here hangs on handing the store an expectation rather than
     * reading state and then writing it. The validation in completeDeepLink
     * happens a moment earlier, and a recovery or a competing link can land in
     * between; passing the generation we believed was current means such a
     * write fails instead of overwriting whatever replaced it.
     *
     * @param  bool  $replace  Whether the token carried the replace mark, which
     *                         is the only thing that authorises moving a
     *                         verified enrollment.
     * @param  string|null  $provenGeneration  For a replacement, the generation
     *                         the token proved; it becomes the CAS expectation.
     */
    private function bind(
        string $userId,
        string $chatId,
        bool $replace = false,
        ?string $provenGeneration = null,
    ): LinkResult {
        $existing = $this->identities->findByUserId($userId);
        $replacing = null;

        if ($existing !== null && $existing->isVerified()) {
            // Re-presenting the same chat is a double submit, not a conflict.
            if ($existing->chatId === $chatId) {
                return LinkResult::linked($existing);
            }

            if (! $replace) {
                return LinkResult::failed(ErrorCode::AlreadyLinked);
            }

            $replacing = $existing;
        }

        $expected = $replace ? $provenGeneration : ($existing?->generation ?? null);

        $holder = $this->identities->findByChatId($chatId);

        if ($holder !== null && $holder->userId !== $userId) {
            $this->logger->warning('telegram-2fa: chat already linked to another account', [
                'user_id' => $userId,
            ]);

            return LinkResult::failed(ErrorCode::AlreadyLinked);
        }

        try {
            // One write. It either moves the enrollment or changes nothing, so
            // a replacement onto an unavailable chat — or one overtaken by a
            // recovery — leaves the existing enrollment exactly as it was,
            // rather than stripping the account of its second factor as a side
            // effect of a request that failed.
            $identity = $this->identities->transition(
                $userId,
                $chatId,
                $expected,
                $this->nextGeneration(),
            );
        } catch (ChatAlreadyLinked) {
            // The store's uniqueness constraint caught what the check above
            // raced past. The loser's existing enrollment is untouched.
            return LinkResult::failed(ErrorCode::AlreadyLinked);
        }

        if ($identity === null) {
            // The enrollment changed under us. For a replacement that means the
            // token is stale; for a first link, that another request got there.
            $this->logger->warning('telegram-2fa: enrollment changed during link', [
                'user_id' => $userId,
                'replace' => $replace,
            ]);

            return LinkResult::failed(
                $replace ? ErrorCode::InvalidToken : ErrorCode::AlreadyLinked
            );
        }

        if ($replacing !== null) {
            // Any code in flight was delivered to the chat that is no longer
            // the factor, so whoever still has that chat could use it. The
            // generation has already changed, so such a code is unusable even
            // if this cleanup loses a race; this merely stops it lingering.
            $this->clearPending($userId);

            // Afterwards, so a failed replacement never announces one. If the
            // user did not request this, that message is how they find out.
            $this->telegram->sendMessage(
                $replacing->chatId ?? '',
                $this->messages->unlinked($this->config->appName),
            );

            $this->logger->info('telegram-2fa: factor replaced', ['user_id' => $userId]);

            return LinkResult::linked($identity);
        }

        $this->logger->info('telegram-2fa: linked', ['user_id' => $userId]);

        return LinkResult::linked($identity);
    }

    /**
     * Drop any challenge in flight, and the cooldown with it.
     */
    private function clearPending(string $userId): void
    {
        $this->store->forget($this->config->key('code', $userId));
        $this->store->forget($this->config->key('cooldown', $userId));
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

        if (($blocked = $this->reserveSend($userId)) !== null) {
            return ChallengeResult::failed(ErrorCode::Cooldown, $blocked);
        }

        $challenge = $this->issue($userId, $purpose, $identity->generation);

        $sent = $this->telegram->sendMessage(
            $identity->chatId ?? '',
            $this->messages->code($challenge['code'], $this->config->codeTtl),
        );

        if (! $sent) {
            // Drop the code rather than leaving one live that the user never
            // received: otherwise the account sits in a state where the only
            // way forward is to wait out the cooldown. Conditionally, so a
            // slow failure cannot delete a code issued after it.
            $this->discardChallenge($userId, $challenge['challenge_id']);

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

        if (($blocked = $this->reserveSend($identity->userId)) !== null) {
            return ChallengeResult::failed(ErrorCode::Cooldown, $blocked);
        }

        $challenge = $this->issue($identity->userId, $purpose, $identity->generation);

        $sent = $this->telegram->sendMessage(
            $chatId,
            $this->messages->code($challenge['code'], $this->config->codeTtl),
        );

        if (! $sent) {
            $this->discardChallenge($identity->userId, $challenge['challenge_id']);

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
    /**
     * @return array{code: string, challenge_id: string}
     */
    private function issue(string $userId, string $purpose, ?string $generation): array
    {
        $code = $this->codes->twoFactorCode($this->config->codeLength);
        $challengeId = bin2hex(random_bytes(8));

        $this->store->put(
            $this->config->key('code', $userId),
            [
                'hash' => $this->hasher->hash($code, $userId),
                'expires_at' => $this->clock->now() + $this->config->codeTtl,
                'attempts' => 0,
                'purpose' => $purpose,
                // The enrollment this challenge belongs to. Verification
                // refuses a challenge from a superseded enrollment, which is
                // what stops a code outliving the chat it was sent to.
                'generation' => $generation,
                // Identifies this particular challenge, so a cleanup for a
                // failed delivery can tell its own code from a newer one.
                'challenge_id' => $challengeId,
            ],
            $this->config->codeTtl,
        );

        return ['code' => $code, 'challenge_id' => $challengeId];
    }

    /**
     * Drop a challenge only if it is still the one we issued.
     *
     * A delivery failure must not delete a newer challenge. That is reachable:
     * if sending blocks past the cooldown, the user can be issued a fresh code
     * before this handler runs, and an unconditional delete would throw away a
     * code the user is holding.
     */
    private function discardChallenge(string $userId, string $challengeId): void
    {
        $key = $this->config->key('code', $userId);
        $record = $this->store->take($key);

        if (! is_array($record)) {
            return;
        }

        if (($record['challenge_id'] ?? null) !== $challengeId) {
            // Someone else's challenge. Put it back as we found it.
            $this->store->put(
                $key,
                $record,
                max(1, (int) ($record['expires_at'] ?? 0) - $this->clock->now()),
            );

            return;
        }

        $this->store->forget($this->config->key('cooldown', $userId));
    }

    /**
     * Reserve the right to send, atomically.
     *
     * Checking for a cooldown and then writing one is two operations, and two
     * challenges arriving together both see no cooldown and both send. add()
     * makes the write itself the check, so exactly one caller wins the window.
     *
     * @return int|null The timestamp another send becomes possible, when this
     *                  caller lost the reservation; null when it won.
     */
    private function reserveSend(string $userId): ?int
    {
        $key = $this->config->key('cooldown', $userId);
        $nextSendAt = $this->clock->now() + $this->config->cooldown;

        if ($this->store->add($key, $nextSendAt, $this->config->cooldown)) {
            return null;
        }

        $held = $this->store->get($key);

        // Fall back to the full cooldown if the value has gone between the
        // failed add and this read, rather than reporting a time in the past.
        return is_numeric($held) ? (int) $held : $nextSendAt;
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

        // Take the record, rather than read it and delete it later. Those are
        // two operations with a gap between them, and two verifications
        // arriving together both read the live record, both match, and both
        // succeed — a single-use code used twice, with the attempt counter
        // losing increments to the same race. Taking it means the winner holds
        // the only copy: it either consumes the code or writes it back with one
        // more attempt spent, while a concurrent caller finds nothing.
        $record = $this->store->take($key);

        if (! is_array($record) || ! isset($record['hash'])) {
            return VerificationResult::fail(ErrorCode::Expired);
        }

        $attempts = (int) ($record['attempts'] ?? 0);

        // The record is already gone in each of these branches, which is what
        // we want: a spent or expired code should not come back.
        if ($attempts >= $this->config->maxAttempts) {
            return VerificationResult::fail(ErrorCode::TooManyAttempts, 0);
        }

        if ((int) ($record['expires_at'] ?? 0) < $this->clock->now()) {
            return VerificationResult::fail(ErrorCode::Expired);
        }

        // The enrollment this challenge belongs to must still be the current
        // one. Anything that changed it — a replacement, an unlink, a recovery
        // — revoked this challenge, and the record is already gone because we
        // took it, so a revoked challenge dies here rather than being restored.
        //
        // This check, not the cleanup in bind(), is what makes revocation
        // sound: cleanup races a concurrent verification, while this cannot.
        if (! $this->generationMatches($userId, $record['generation'] ?? null)) {
            $this->logger->warning('telegram-2fa: challenge from a superseded enrollment', [
                'user_id' => $userId,
            ]);

            return VerificationResult::fail(ErrorCode::Expired);
        }

        if (! $this->purposeSatisfied((string) ($record['purpose'] ?? ''), $purpose)) {
            // A code minted to confirm a login should not also confirm a
            // withdrawal. Count it as an attempt rather than a free retry, and
            // report it as `invalid`: telling the caller that a live code
            // exists for some other purpose is information it has not proved
            // it should have.
            return $this->recordFailedAttempt($key, $record, $attempts, $userId);
        }

        // Bound to the account, so a digest lifted from the store cannot be
        // matched against another user's code.
        if (! $this->hasher->matches((string) $record['hash'], trim($code), $userId)) {
            return $this->recordFailedAttempt($key, $record, $attempts, $userId);
        }

        $this->logger->info('telegram-2fa: verified', [
            'user_id' => $userId,
            'purpose' => $record['purpose'] ?? null,
        ]);

        return VerificationResult::pass();
    }

    /**
     * Whether a stored code may be used for the purpose being requested.
     *
     * An on-demand code is general-purpose by default, because it cannot know
     * what it is for and the user asked for it deliberately. That is a policy
     * rather than a law: requesting a code does not prove intent to perform any
     * particular action, so an installation that wants privileged steps to
     * issue their own code can narrow it with onDemandSatisfies.
     */
    private function purposeSatisfied(string $stored, string $requested): bool
    {
        if ($stored === $requested) {
            return true;
        }

        if ($stored !== self::PURPOSE_ON_DEMAND) {
            return false;
        }

        return $this->config->onDemandSatisfies === null
            || in_array($requested, $this->config->onDemandSatisfies, true);
    }

    /**
     * Whether a challenge belongs to the account's current enrollment.
     *
     * A challenge issued before the enrollment generation existed (a row
     * migrated from an older version) is accepted only while the account has no
     * generation at all, so upgrading does not invalidate codes in flight.
     */
    private function generationMatches(string $userId, mixed $generation): bool
    {
        $current = $this->identities->findByUserId($userId)?->generation;

        if ($current === null) {
            return $generation === null;
        }

        return is_string($generation) && hash_equals($current, $generation);
    }

    /**
     * @param  array<string, mixed>  $record
     */
    private function recordFailedAttempt(
        string $key,
        array $record,
        int $attempts,
        string $userId,
    ): VerificationResult
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

        if (! $this->detach($identity, $identity->generation)) {
            // The enrollment moved while we were verifying, so the code we
            // just accepted no longer refers to what is stored.
            return VerificationResult::fail(ErrorCode::Expired);
        }

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

        // Unconditional: the caller has proved identity by other means, and a
        // recovery must not be blocked by whatever the account's state is.
        $this->detach($identity, IdentityStore::ANY_GENERATION);

        $this->logger->warning('telegram-2fa: unlinked via external proof', [
            'user_id' => $userId,
            'reason' => $reason,
        ]);

        return true;
    }

    /**
     * Remove the enrollment and revoke everything that referred to it.
     *
     * The generation is advanced even though no chat remains, which is the
     * whole reason it is stored separately from the chat id: a replacement
     * token or a challenge minted before this point stays void afterwards, and
     * would otherwise come back to life the moment the user links again.
     *
     * @param  string|null  $expected  The generation the caller verified
     *                                 against, or ANY_GENERATION for a
     *                                 recovery, where the caller has already
     *                                 proved identity another way and must not
     *                                 be blocked by a concurrent change.
     * @return bool Whether the transition applied.
     */
    private function detach(Identity $identity, ?string $expected): bool
    {
        $moved = $this->identities->transition(
            $identity->userId,
            null,
            $expected,
            $this->nextGeneration(),
        );

        if ($moved === null) {
            $this->logger->warning('telegram-2fa: enrollment changed during unlink', [
                'user_id' => $identity->userId,
            ]);

            return false;
        }

        $this->clearPending($identity->userId);

        // Best effort: the user should hear that their factor was removed even
        // if, especially if, they did not do it themselves.
        if ($identity->chatId !== null) {
            $this->telegram->sendMessage(
                $identity->chatId,
                $this->messages->unlinked($this->config->appName),
            );
        }

        $this->logger->info('telegram-2fa: unlinked', ['user_id' => $identity->userId]);

        return true;
    }
}
