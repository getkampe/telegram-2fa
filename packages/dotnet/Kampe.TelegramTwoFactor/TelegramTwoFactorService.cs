namespace Kampe.TelegramTwoFactor;

/// <summary>
/// Telegram as a second authentication factor.
/// </summary>
/// <remarks>
/// The whole protocol with no framework underneath it: linking (three flows),
/// challenge (two directions), verification, unlinking. Everything it touches
/// arrives through an interface, so the same class runs on Redis and SQL Server or
/// on dictionaries in a test.
/// <para>
/// <strong>On async and critical sections.</strong> Every store call is awaited,
/// and no lock is ever held across one. That is not an accident of style: in an
/// event loop an await inside a critical section is a suspension point, which is
/// how the Node port once let two concurrent verifications of a single code both
/// succeed. Here the atomicity lives entirely in the store's own primitives -
/// <see cref="ICodeStore.TakeAsync"/>, <see cref="ICodeStore.AddAsync"/> and
/// <see cref="IIdentityStore.TransitionAsync"/> - so there is no critical section
/// in this class for an await to split. C# helps: the compiler refuses an await
/// inside a <c>lock</c>.
/// </para>
/// <para>See SPEC.md for the normative protocol this implements.</para>
/// </remarks>
public class TelegramTwoFactorService
{
    private readonly ICodeStore _store;
    private readonly IIdentityStore _identities;
    private readonly ITelegramClient _telegram;
    private readonly IMessages _messages;
    private readonly IClock _clock;
    private readonly IEventLog _log;
    private readonly CodeGenerator _codes;
    private readonly CodeHasher _hasher;

    /// <summary>Creates the service.</summary>
    public TelegramTwoFactorService(
        Config config,
        ICodeStore store,
        IIdentityStore identities,
        ITelegramClient telegram,
        IMessages messages,
        IClock? clock = null,
        IEventLog? log = null,
        CodeGenerator? codes = null,
        CodeHasher? hasher = null)
    {
        Config = config ?? throw new ArgumentNullException(nameof(config));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _identities = identities ?? throw new ArgumentNullException(nameof(identities));
        _telegram = telegram ?? throw new ArgumentNullException(nameof(telegram));
        _messages = messages ?? throw new ArgumentNullException(nameof(messages));
        _clock = clock ?? new SystemClock();
        _log = log ?? NullEventLog.Instance;
        _codes = codes ?? new CodeGenerator();
        _hasher = hasher ?? new CodeHasher(config.HashAlgorithm, config.HashPepper);
    }

    /// <summary>The configuration this service was built with.</summary>
    public Config Config { get; }

    // ------------------------------------------------------------- identity

    /// <summary>Whether this account has a proven Telegram second factor.</summary>
    public async Task<bool> IsLinkedAsync(string userId, CancellationToken ct = default) =>
        (await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false)).IsVerifiedFactor();

    /// <summary>The enrollment row for an account, linked or not.</summary>
    public Task<Identity?> IdentityAsync(string userId, CancellationToken ct = default) =>
        _identities.FindByUserIdAsync(userId, ct);

    /// <summary>The enrollment behind a chat, for the webhook side of the protocol.</summary>
    public Task<Identity?> IdentityForChatAsync(string chatId, CancellationToken ct = default) =>
        _identities.FindByChatIdAsync(chatId, ct);

    // -------------------------------------------------------------- linking

    /// <summary>
    /// Begins the deeplink flow: mints a nonce bound to this account.
    /// </summary>
    /// <remarks>
    /// Hand the returned url to the user as a button, or as a QR code when they are
    /// on a desktop with Telegram on their phone. The token is bound to the account
    /// before it ever reaches Telegram, which is what makes this flow preferable to
    /// the paste flow: there is no window in which a token is valid for whoever
    /// happens to present it.
    /// <para>
    /// Minting is harmless for an already-linked account, so this does not check;
    /// the check happens in <see cref="CompleteDeepLinkAsync"/>.
    /// </para>
    /// </remarks>
    public async Task<LinkRequest> StartDeepLinkAsync(string userId, CancellationToken ct = default)
    {
        var token = _codes.DeepLinkToken();
        var expiresAt = _clock.Now + Config.LinkTtl;

        await _store.PutAsync(
            Config.Key("link", _hasher.Hash(token)),
            Wire.Write(new LinkRecord { UserId = userId, ExpiresAt = expiresAt }),
            Config.LinkTtl,
            ct).ConfigureAwait(false);

        _log.Info("telegram-2fa: deeplink issued", Context(("user_id", userId)));

        return new LinkRequest(token, expiresAt, Config.DeepLinkUrl(token));
    }

    /// <summary>Finishes the deeplink flow, from the /start payload in a webhook update.</summary>
    public async Task<LinkResult> CompleteDeepLinkAsync(
        string token,
        string chatId,
        CancellationToken ct = default)
    {
        // Single use, and taken atomically: a token read now and deleted later can
        // be resolved twice by two concurrent /start messages, and a token that
        // survives a failed attempt can be retried by anyone who saw it - and it
        // travelled through a chat, so others may have.
        var raw = await _store.TakeAsync(Config.Key("link", _hasher.Hash(token)), ct).ConfigureAwait(false);
        var record = Wire.Read<LinkRecord>(raw);

        if (record is null || string.IsNullOrEmpty(record.UserId))
        {
            _log.Warn("telegram-2fa: deeplink token not resolvable", Context(("chat_id", chatId)));

            return LinkResult.Failed(ErrorCode.InvalidToken);
        }

        if (record.ExpiresAt < _clock.Now)
        {
            return LinkResult.Failed(ErrorCode.InvalidToken);
        }

        var replace = record.Replace == true;
        var proven = record.Generation;
        var userId = record.UserId;

        // A replacement token carries authority over an existing enrollment, so it
        // is only valid against the one whose possession was proved. If that
        // enrollment has since changed - recovered through support, unlinked, or
        // already replaced - the proof no longer refers to anything.
        if (replace && !await GenerationCurrentAsync(userId, proven, ct).ConfigureAwait(false))
        {
            _log.Warn("telegram-2fa: stale replacement token rejected", Context(("user_id", userId)));

            return LinkResult.Failed(ErrorCode.InvalidToken);
        }

        return await BindAsync(userId, chatId, replace, proven, ct).ConfigureAwait(false);
    }

    /// <summary>Begins the paste flow, from the bot side: mints a code bound to this chat.</summary>
    public async Task<LinkRequest> StartPasteLinkAsync(string chatId, CancellationToken ct = default)
    {
        var code = _codes.LinkCode(Config.LinkCodeLength);
        var expiresAt = _clock.Now + Config.LinkTtl;

        await _store.PutAsync(
            Config.Key("link", _hasher.Hash(code)),
            Wire.Write(new LinkRecord { ChatId = chatId, ExpiresAt = expiresAt }),
            Config.LinkTtl,
            ct).ConfigureAwait(false);

        _log.Info("telegram-2fa: paste link code issued");

        return new LinkRequest(code, expiresAt, null);
    }

    /// <summary>
    /// Finishes the paste flow, from an authenticated page in your application.
    /// </summary>
    /// <remarks>
    /// Two things this cannot check are the caller's: that <paramref name="userId"/>
    /// comes from the session rather than the request body, and that the endpoint is
    /// rate-limited. Without the rate limit the attempt budget on this flow is
    /// unbounded, and link codes share one namespace across all users.
    /// </remarks>
    public async Task<LinkResult> CompletePasteLinkAsync(
        string userId,
        string code,
        CancellationToken ct = default)
    {
        var normalised = (code ?? string.Empty).Trim().ToUpperInvariant();
        var raw = await _store.TakeAsync(Config.Key("link", _hasher.Hash(normalised)), ct).ConfigureAwait(false);
        var record = Wire.Read<LinkRecord>(raw);

        if (record is null || string.IsNullOrEmpty(record.ChatId))
        {
            _log.Warn("telegram-2fa: paste code not resolvable", Context(("user_id", userId)));

            return LinkResult.Failed(ErrorCode.InvalidToken);
        }

        if (record.ExpiresAt < _clock.Now)
        {
            return LinkResult.Failed(ErrorCode.InvalidToken);
        }

        return await BindAsync(userId, record.ChatId, false, null, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Begins moving the factor to a different Telegram account.
    /// </summary>
    /// <remarks>
    /// Linking never silently moves a verified enrollment, because a flow that did
    /// would let anyone holding a session attach their own chat. So replacement is
    /// explicit and costs a code from the chat being replaced.
    /// <para>
    /// A user who has lost the old chat entirely cannot do this, and belongs in
    /// <see cref="UnlinkAfterExternalProofAsync"/> instead.
    /// </para>
    /// </remarks>
    public async Task<ReplacementResult> StartChatReplacementAsync(
        string userId,
        string code,
        CancellationToken ct = default)
    {
        var identity = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (!identity.IsVerifiedFactor())
        {
            return ReplacementResult.Refused(VerificationResult.Failed(ErrorCode.NotLinked));
        }

        // Captured *before* verifying, because this is the enrollment the user is
        // about to prove possession of. It is what the token must record.
        var proven = identity.Generation;

        var proof = await VerifyAsync(userId, code, Purpose.Replace, ct).ConfigureAwait(false);

        if (!proof.Ok)
        {
            return ReplacementResult.Refused(proof);
        }

        if (string.IsNullOrEmpty(proven))
        {
            // A row enrolled before the generation existed. Assign one, conditional
            // on it still being absent - which doubles as the check below: if
            // anything changed the enrollment while the code was being verified, the
            // generation is no longer absent and this declines.
            var assigned = await _identities.TransitionAsync(
                userId, identity.ChatId, null, _codes.EnrollmentGeneration(), ct).ConfigureAwait(false);

            if (!assigned.IsVerifiedFactor())
            {
                return ReplacementResult.Refused(VerificationResult.Failed(ErrorCode.Expired));
            }

            return ReplacementResult.Authorised(
                await MintReplacementTokenAsync(userId, assigned.Generation!, ct).ConfigureAwait(false));
        }

        // Confirm the enrollment did not move while the code was being verified, and
        // reject if it did. What must never happen is adopting the generation read
        // *after* verification: a recovery landing in that window would have its own
        // new generation, and recording that would hand this token authority over an
        // enrollment the user never proved.
        var after = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (!after.IsVerifiedFactor() || !ConstantTime.Equals(after.Generation, proven))
        {
            _log.Warn(
                "telegram-2fa: enrollment changed during replacement authorisation",
                Context(("user_id", userId)));

            return ReplacementResult.Refused(VerificationResult.Failed(ErrorCode.Expired));
        }

        return ReplacementResult.Authorised(
            await MintReplacementTokenAsync(userId, proven, ct).ConfigureAwait(false));
    }

    // ------------------------------------------------------------ challenge

    /// <summary>
    /// Issues a code and sends it to the linked chat.
    /// </summary>
    /// <remarks>
    /// The code is not in the return value. It is generated, hashed into the store,
    /// handed to Telegram, and dropped.
    /// </remarks>
    public async Task<ChallengeResult> PushAsync(
        string userId,
        string purpose = Purpose.Login,
        CancellationToken ct = default)
    {
        var identity = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (!identity.IsVerifiedFactor())
        {
            return ChallengeResult.Failed(ErrorCode.NotLinked);
        }

        var blocked = await ReserveSendAsync(userId, ct).ConfigureAwait(false);

        if (blocked is not null)
        {
            return ChallengeResult.Failed(ErrorCode.Cooldown, blocked);
        }

        var (code, challengeId) = await IssueAsync(userId, purpose, identity.Generation, ct).ConfigureAwait(false);

        var sent = await _telegram.SendMessageAsync(
            identity.ChatId!, _messages.Code(code, Config.CodeTtl), null, ct).ConfigureAwait(false);

        if (!sent)
        {
            // Drop the code rather than leaving one live that the user never
            // received. Conditionally, so a slow failure cannot delete a code issued
            // after it.
            await DiscardChallengeAsync(userId, challengeId, ct).ConfigureAwait(false);
            _log.Error("telegram-2fa: delivery failed", Context(("user_id", userId)));

            return ChallengeResult.Failed(ErrorCode.SendFailed);
        }

        _log.Info("telegram-2fa: code sent", Context(("user_id", userId), ("purpose", purpose)));

        return ChallengeResult.Sent(_clock.Now + Config.CodeTtl, _clock.Now + Config.Cooldown);
    }

    /// <summary>
    /// The user asked the bot for a code.
    /// </summary>
    /// <remarks>
    /// Writes the same store key as <see cref="PushAsync"/>, so one verification
    /// call accepts a code from either direction - see the single-key rule in
    /// SPEC.md section 4.
    /// </remarks>
    public async Task<ChallengeResult> PullAsync(
        string chatId,
        string purpose = Purpose.OnDemand,
        CancellationToken ct = default)
    {
        var identity = await _identities.FindByChatIdAsync(chatId, ct).ConfigureAwait(false);

        if (!identity.IsVerifiedFactor())
        {
            return ChallengeResult.Failed(ErrorCode.NotLinked);
        }

        var userId = identity.UserId;
        var blocked = await ReserveSendAsync(userId, ct).ConfigureAwait(false);

        if (blocked is not null)
        {
            return ChallengeResult.Failed(ErrorCode.Cooldown, blocked);
        }

        var (code, challengeId) = await IssueAsync(userId, purpose, identity.Generation, ct).ConfigureAwait(false);

        var sent = await _telegram.SendMessageAsync(
            chatId, _messages.Code(code, Config.CodeTtl), null, ct).ConfigureAwait(false);

        if (!sent)
        {
            await DiscardChallengeAsync(userId, challengeId, ct).ConfigureAwait(false);

            return ChallengeResult.Failed(ErrorCode.SendFailed);
        }

        _log.Info("telegram-2fa: code issued on demand", Context(("user_id", userId)));

        return ChallengeResult.Sent(_clock.Now + Config.CodeTtl, _clock.Now + Config.Cooldown);
    }

    // --------------------------------------------------------- verification

    /// <summary>
    /// Checks a submitted code.
    /// </summary>
    /// <remarks>
    /// Single use on success, attempt-budgeted on failure, fixed-time throughout.
    /// <paramref name="purpose"/> must match what the code was issued for and
    /// defaults to login exactly as <see cref="PushAsync"/> does; there is
    /// deliberately no way to skip the check, because a default of "compare against
    /// nothing" means the binding does nothing unless every call site opts in, and
    /// the call site that forgets is the one that matters.
    /// </remarks>
    public async Task<VerificationResult> VerifyAsync(
        string userId,
        string code,
        string purpose = Purpose.Login,
        CancellationToken ct = default)
    {
        var key = Config.Key("code", userId);

        // Take the record, rather than read it and delete it later. Those are two
        // operations with a gap between them, and two verifications arriving
        // together both read the live record, both match, and both succeed - a
        // single-use code used twice, with the attempt counter losing increments to
        // the same race.
        var raw = await _store.TakeAsync(key, ct).ConfigureAwait(false);
        var record = Wire.Read<ChallengeRecord>(raw);

        if (record is null || string.IsNullOrEmpty(record.Hash))
        {
            return VerificationResult.Failed(ErrorCode.Expired);
        }

        var attempts = record.Attempts;

        // The record is already gone in each of these branches, which is what we
        // want: a spent or expired code should not come back.
        if (attempts >= Config.MaxAttempts)
        {
            return VerificationResult.Failed(ErrorCode.TooManyAttempts, 0);
        }

        if (record.ExpiresAt < _clock.Now)
        {
            return VerificationResult.Failed(ErrorCode.Expired);
        }

        // The enrollment this challenge belongs to must still be current. Anything
        // that changed it revoked this challenge, and the record is already gone
        // because we took it. This check, not the cleanup in Bind, is what makes
        // revocation sound: cleanup races a concurrent verification, while this
        // cannot.
        if (!await GenerationMatchesAsync(userId, record.Generation, ct).ConfigureAwait(false))
        {
            _log.Warn("telegram-2fa: challenge from a superseded enrollment", Context(("user_id", userId)));

            return VerificationResult.Failed(ErrorCode.Expired);
        }

        // A code minted to confirm a login should not also confirm a withdrawal.
        // Count it as an attempt rather than a free retry, and report invalid:
        // telling the caller a live code exists for some other purpose is
        // information it has not proved it should have.
        if (!PurposeSatisfied(record.Purpose ?? string.Empty, purpose))
        {
            return await RecordFailedAttemptAsync(key, record, attempts, userId, ct).ConfigureAwait(false);
        }

        if (!_hasher.Matches(record.Hash, (code ?? string.Empty).Trim(), userId))
        {
            return await RecordFailedAttemptAsync(key, record, attempts, userId, ct).ConfigureAwait(false);
        }

        _log.Info("telegram-2fa: verified", Context(("user_id", userId), ("purpose", record.Purpose)));

        return VerificationResult.Passed();
    }

    // ------------------------------------------------------------ unlinking

    /// <summary>
    /// Removes the factor, proving possession of it first.
    /// </summary>
    /// <remarks>
    /// Unlinking is the step an attacker with a stolen session but no phone needs,
    /// so it demands the same proof as any other protected action.
    /// </remarks>
    public async Task<VerificationResult> UnlinkAsync(
        string userId,
        string code,
        CancellationToken ct = default)
    {
        var identity = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (!identity.IsVerifiedFactor())
        {
            return VerificationResult.Failed(ErrorCode.NotLinked);
        }

        // Under Purpose.Unlink, so a code pushed for a login cannot remove the
        // factor. A code the user fetched with /code still works, because on-demand
        // codes are general-purpose.
        var result = await VerifyAsync(userId, code, Purpose.Unlink, ct).ConfigureAwait(false);

        if (!result.Ok)
        {
            return result;
        }

        // The enrollment moved while we were verifying, so the code we just accepted
        // no longer refers to what is stored.
        if (!await DetachAsync(identity, identity.Generation, ct).ConfigureAwait(false))
        {
            return VerificationResult.Failed(ErrorCode.Expired);
        }

        return VerificationResult.Passed();
    }

    /// <summary>
    /// Removes the factor when another factor has already proved the request.
    /// </summary>
    /// <remarks>
    /// For recovery paths: the user still has their authenticator, or passed an
    /// out-of-band check, but has lost the Telegram account. The caller takes
    /// responsibility for that proof - this method performs none.
    /// </remarks>
    public async Task<bool> UnlinkAfterExternalProofAsync(
        string userId,
        string reason,
        CancellationToken ct = default)
    {
        var identity = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (identity is null)
        {
            return false;
        }

        // Unconditional: the caller has proved identity by other means, and a
        // recovery must not be blocked by whatever the account's state is.
        await DetachAsync(identity, Generations.Any, ct).ConfigureAwait(false);

        _log.Warn(
            "telegram-2fa: unlinked via external proof",
            Context(("user_id", userId), ("reason", reason)));

        return true;
    }

    // ---------------------------------------------------------------- internals

    /// <summary>
    /// Stores a replacement token against exactly one enrollment generation.
    /// </summary>
    /// <remarks>
    /// Separate so there is a single place the generation is written, and so no
    /// caller can pass one it read later than the proof.
    /// </remarks>
    private async Task<LinkRequest> MintReplacementTokenAsync(
        string userId,
        string provenGeneration,
        CancellationToken ct)
    {
        var token = _codes.DeepLinkToken();
        var expiresAt = _clock.Now + Config.LinkTtl;

        await _store.PutAsync(
            Config.Key("link", _hasher.Hash(token)),
            Wire.Write(new LinkRecord
            {
                UserId = userId,
                ExpiresAt = expiresAt,
                Replace = true,
                Generation = provenGeneration,
            }),
            Config.LinkTtl,
            ct).ConfigureAwait(false);

        _log.Info("telegram-2fa: chat replacement authorised", Context(("user_id", userId)));

        return new LinkRequest(token, expiresAt, Config.DeepLinkUrl(token));
    }

    /// <summary>
    /// Records the enrollment, as one conditional transition.
    /// </summary>
    /// <remarks>
    /// Everything here hangs on handing the store an expectation rather than reading
    /// state and then writing it. The validation above happens a moment earlier, and
    /// a recovery or a competing link can land in between; passing the generation we
    /// believed was current means such a write fails instead of overwriting whatever
    /// replaced it.
    /// </remarks>
    private async Task<LinkResult> BindAsync(
        string userId,
        string chatId,
        bool replace,
        string? provenGeneration,
        CancellationToken ct)
    {
        var existing = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);
        Identity? replacing = null;

        if (existing.IsVerifiedFactor())
        {
            // Re-presenting the same chat is a double submit, not a conflict.
            if (existing.ChatId == chatId)
            {
                return LinkResult.Linked(existing);
            }

            if (!replace)
            {
                return LinkResult.Failed(ErrorCode.AlreadyLinked);
            }

            replacing = existing;
        }

        var expected = replace ? provenGeneration : existing?.Generation;
        var holder = await _identities.FindByChatIdAsync(chatId, ct).ConfigureAwait(false);

        if (holder is not null && holder.UserId != userId)
        {
            _log.Warn(
                "telegram-2fa: chat already linked to another account",
                Context(("user_id", userId)));

            return LinkResult.Failed(ErrorCode.AlreadyLinked);
        }

        Identity? identity;

        try
        {
            // One write. It either moves the enrollment or changes nothing, so a
            // replacement onto an unavailable chat - or one overtaken by a recovery -
            // leaves the existing enrollment exactly as it was, rather than stripping
            // the account of its second factor as a side effect of a request that
            // failed.
            identity = await _identities.TransitionAsync(
                userId, chatId, expected, _codes.EnrollmentGeneration(), ct).ConfigureAwait(false);
        }
        catch (ChatAlreadyLinkedException)
        {
            // The store's uniqueness constraint caught what the check above raced
            // past. The loser's existing enrollment is untouched.
            return LinkResult.Failed(ErrorCode.AlreadyLinked);
        }

        if (identity is null)
        {
            _log.Warn(
                "telegram-2fa: enrollment changed during link",
                Context(("user_id", userId), ("replace", replace)));

            return LinkResult.Failed(replace ? ErrorCode.InvalidToken : ErrorCode.AlreadyLinked);
        }

        if (replacing is not null)
        {
            // Any code in flight was delivered to the chat that is no longer the
            // factor. The generation has already changed, so such a code is unusable
            // even if this cleanup loses a race; this stops it lingering.
            await ClearPendingAsync(userId, ct).ConfigureAwait(false);

            // Afterwards, so a failed replacement never announces one.
            if (replacing.ChatId is not null)
            {
                await _telegram.SendMessageAsync(
                    replacing.ChatId, _messages.Unlinked(Config.AppName), null, ct).ConfigureAwait(false);
            }

            _log.Info("telegram-2fa: factor replaced", Context(("user_id", userId)));

            return LinkResult.Linked(identity);
        }

        _log.Info("telegram-2fa: linked", Context(("user_id", userId)));

        return LinkResult.Linked(identity);
    }

    private async Task<(string Code, string ChallengeId)> IssueAsync(
        string userId,
        string purpose,
        string? generation,
        CancellationToken ct)
    {
        var code = _codes.TwoFactorCode(Config.CodeLength);
        var challengeId = _codes.ChallengeId();

        await _store.PutAsync(
            Config.Key("code", userId),
            Wire.Write(new ChallengeRecord
            {
                // Bound to the account, so a digest lifted from the store cannot be
                // matched against another user's code.
                Hash = _hasher.Hash(code, userId),
                ExpiresAt = _clock.Now + Config.CodeTtl,
                Attempts = 0,
                Purpose = purpose,
                Generation = generation,
                ChallengeId = challengeId,
            }),
            Config.CodeTtl,
            ct).ConfigureAwait(false);

        return (code, challengeId);
    }

    /// <summary>
    /// Drops a challenge only if it is still the one we issued.
    /// </summary>
    /// <remarks>
    /// A delivery failure must not delete a newer challenge. That is reachable: if
    /// sending blocks past the cooldown, the user can be issued a fresh code before
    /// this handler runs, and an unconditional delete would throw away a code the
    /// user is holding.
    /// </remarks>
    private async Task DiscardChallengeAsync(string userId, string challengeId, CancellationToken ct)
    {
        var key = Config.Key("code", userId);
        var raw = await _store.TakeAsync(key, ct).ConfigureAwait(false);
        var record = Wire.Read<ChallengeRecord>(raw);

        if (record is null)
        {
            return;
        }

        if (record.ChallengeId != challengeId)
        {
            // Someone else's challenge. Put it back exactly as we found it, raw, so
            // a field another implementation wrote is not dropped in the round trip.
            await _store.PutAsync(
                key, raw!, (int)Math.Max(1, record.ExpiresAt - _clock.Now), ct).ConfigureAwait(false);

            return;
        }

        await _store.ForgetAsync(Config.Key("cooldown", userId), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Reserves the right to send, atomically.
    /// </summary>
    /// <remarks>
    /// Checking for a cooldown and then writing one is two operations, and two
    /// challenges arriving together both see no cooldown and both send.
    /// <see cref="ICodeStore.AddAsync"/> makes the write itself the check.
    /// </remarks>
    /// <returns>Null when the send may proceed, else when the next one is permitted.</returns>
    private async Task<long?> ReserveSendAsync(string userId, CancellationToken ct)
    {
        var key = Config.Key("cooldown", userId);
        var nextSendAt = _clock.Now + Config.Cooldown;

        if (await _store.AddAsync(key, Wire.WriteTimestamp(nextSendAt), Config.Cooldown, ct).ConfigureAwait(false))
        {
            return null;
        }

        var held = await _store.GetAsync(key, ct).ConfigureAwait(false);

        // Coerced, not compared: a store may hand back a quoted number, and a value
        // we cannot read is no reason to lift the cooldown.
        return Wire.ReadTimestamp(held) ?? nextSendAt;
    }

    private async Task ClearPendingAsync(string userId, CancellationToken ct)
    {
        await _store.ForgetAsync(Config.Key("code", userId), ct).ConfigureAwait(false);
        await _store.ForgetAsync(Config.Key("cooldown", userId), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether a stored code may be used for the purpose being requested.
    /// </summary>
    /// <remarks>
    /// An on-demand code is general-purpose by default, because it cannot know what
    /// it is for and the user asked for it deliberately. That is a policy rather
    /// than a law, so <see cref="Config.OnDemandSatisfies"/> can narrow it.
    /// </remarks>
    private bool PurposeSatisfied(string stored, string requested)
    {
        if (stored == requested)
        {
            return true;
        }

        if (stored != Purpose.OnDemand)
        {
            return false;
        }

        return Config.OnDemandSatisfies is null || Config.OnDemandSatisfies.Contains(requested);
    }

    /// <summary>
    /// Whether a challenge belongs to the account's current enrollment.
    /// </summary>
    /// <remarks>
    /// A challenge issued before the generation existed (a row migrated from an
    /// older version) is accepted only while the account has no generation at all,
    /// so upgrading does not invalidate codes in flight.
    /// </remarks>
    private async Task<bool> GenerationMatchesAsync(string userId, string? generation, CancellationToken ct)
    {
        var current = (await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false))?.Generation;

        if (current is null)
        {
            return generation is null;
        }

        return ConstantTime.Equals(current, generation);
    }

    private async Task<bool> GenerationCurrentAsync(string userId, string? generation, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(generation))
        {
            return false;
        }

        var identity = await _identities.FindByUserIdAsync(userId, ct).ConfigureAwait(false);

        if (!identity.IsVerifiedFactor())
        {
            return false;
        }

        return ConstantTime.Equals(identity.Generation, generation);
    }

    private async Task<VerificationResult> RecordFailedAttemptAsync(
        string key,
        ChallengeRecord record,
        int attempts,
        string userId,
        CancellationToken ct)
    {
        var spent = attempts + 1;
        var remaining = Config.MaxAttempts - spent;

        if (remaining <= 0)
        {
            return VerificationResult.Failed(ErrorCode.TooManyAttempts, 0);
        }

        // Re-stored under the code's own remaining lifetime. A fresh full TTL would
        // let an attacker keep a code alive indefinitely by guessing wrong, removing
        // the time limit altogether.
        //
        // A revocation can land between the take above and this write, so this
        // re-check keeps a dead challenge from being written back. It is best-effort
        // by nature, and does not need to be airtight, because Verify re-checks the
        // generation before accepting anything. A resurrected record is inert.
        if (await GenerationMatchesAsync(userId, record.Generation, ct).ConfigureAwait(false))
        {
            record.Attempts = spent;

            await _store.PutAsync(
                key,
                Wire.Write(record),
                (int)Math.Max(1, record.ExpiresAt - _clock.Now),
                ct).ConfigureAwait(false);
        }

        return VerificationResult.Failed(ErrorCode.Invalid, remaining);
    }

    /// <summary>
    /// Removes the enrollment and revokes everything that referred to it.
    /// </summary>
    /// <remarks>
    /// The generation is advanced even though no chat remains, which is the whole
    /// reason it is stored separately from the chat id: a replacement token or a
    /// challenge minted before this point stays void afterwards, and would otherwise
    /// come back to life the moment the user links again.
    /// </remarks>
    private async Task<bool> DetachAsync(Identity identity, string? expected, CancellationToken ct)
    {
        var moved = await _identities.TransitionAsync(
            identity.UserId, null, expected, _codes.EnrollmentGeneration(), ct).ConfigureAwait(false);

        if (moved is null)
        {
            _log.Warn(
                "telegram-2fa: enrollment changed during unlink",
                Context(("user_id", identity.UserId)));

            return false;
        }

        await ClearPendingAsync(identity.UserId, ct).ConfigureAwait(false);

        // Best effort: the user should hear that their factor was removed even if,
        // especially if, they did not do it themselves.
        if (identity.ChatId is not null)
        {
            await _telegram.SendMessageAsync(
                identity.ChatId, _messages.Unlinked(Config.AppName), null, ct).ConfigureAwait(false);
        }

        _log.Info("telegram-2fa: unlinked", Context(("user_id", identity.UserId)));

        return true;
    }

    private static IReadOnlyDictionary<string, object?> Context(params (string Key, object? Value)[] pairs)
    {
        var result = new Dictionary<string, object?>(pairs.Length, StringComparer.Ordinal);

        foreach (var (key, value) in pairs)
        {
            result[key] = value;
        }

        return result;
    }
}
