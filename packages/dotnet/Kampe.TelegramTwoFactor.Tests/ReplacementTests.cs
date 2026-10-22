using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>SPEC.md 3.3 - moving the factor to a different Telegram account.</summary>
public class ReplacementTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task AProvenReplacementMovesTheFactor()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var result = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(result.Ok);
        Assert.True((await _h.Service.CompleteDeepLinkAsync(result.Request!.Token, "777000222")).Ok);
        Assert.Equal("777000222", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
        Assert.Null(await _h.Service.IdentityForChatAsync("555000111"));
    }

    /// <summary>
    /// The mark that authorises rebinding lives on the stored token. If it were
    /// taken from the resolving call instead, the proof step could be skipped by
    /// presenting an ordinary link token.
    /// </summary>
    [Fact]
    public async Task AnOrdinaryTokenCannotMoveAVerifiedBinding()
    {
        _h.Seed();

        var ordinary = await _h.Service.StartDeepLinkAsync("user-1");

        Assert.Equal(
            ErrorCode.AlreadyLinked,
            (await _h.Service.CompleteDeepLinkAsync(ordinary.Token, "777000222")).Error);
        Assert.Equal("555000111", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
    }

    /// <summary>
    /// A refused replacement must not cost the user the factor they already had.
    /// </summary>
    /// <remarks>
    /// Releasing the old binding before checking the destination made a failed
    /// request strip the account of its second factor - which is what happened in an
    /// earlier revision of the PHP and Node packages.
    /// </remarks>
    [Fact]
    public async Task ARefusedReplacementLeavesTheOriginalFactorIntact()
    {
        _h.Seed("user-1", "555000111");
        _h.Seed("user-2", "777000222");
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var result = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(result.Ok);
        Assert.Equal(
            ErrorCode.AlreadyLinked,
            (await _h.Service.CompleteDeepLinkAsync(result.Request!.Token, "777000222")).Error);

        // The other account keeps its chat...
        Assert.Equal("user-2", (await _h.Service.IdentityForChatAsync("777000222"))!.UserId);
        // ...and so does this one.
        Assert.Equal("555000111", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
    }

    [Fact]
    public async Task ARefusedReplacementDoesNotAnnounceOne()
    {
        _h.Seed("user-1", "555000111");
        _h.Seed("user-2", "777000222");
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var result = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(result.Ok);
        _h.Telegram.Reset();

        await _h.Service.CompleteDeepLinkAsync(result.Request!.Token, "777000222");

        // Telling the user their factor was removed when it was not is its own small
        // incident: they will go looking for an attacker.
        Assert.Empty(_h.Telegram.Sent);
    }

    /// <summary>Authority over a factor must not survive the factor.</summary>
    [Fact]
    public async Task AReplacementTokenIsVoidAfterRecovery()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var stale = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(stale.Ok);

        // The user loses their Telegram account and support recovers them.
        await _h.Service.UnlinkAfterExternalProofAsync("user-1", "verified out of band");
        var fresh = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(fresh.Token, "888000333");

        Assert.Equal(
            ErrorCode.InvalidToken,
            (await _h.Service.CompleteDeepLinkAsync(stale.Request!.Token, "999000444")).Error);
        Assert.Equal("888000333", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
    }

    /// <summary>
    /// What a timestamp fingerprint could not express: chat_id|linked_at repeats when
    /// the same chat is unlinked and relinked inside one second, reviving every token
    /// minted beforehand. The clock never advances here.
    /// </summary>
    [Fact]
    public async Task UnlinkAndRelinkWithinOneSecondInvalidatesOldTokens()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var stale = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(stale.Ok);

        var before = _h.Clock.Now;

        await _h.Service.UnlinkAfterExternalProofAsync("user-1", "user asked");
        var fresh = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(fresh.Token, "555000111");

        Assert.Equal(before, _h.Clock.Now);
        Assert.False((await _h.Service.CompleteDeepLinkAsync(stale.Request!.Token, "999000444")).Ok);
        Assert.Equal("555000111", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
    }

    /// <summary>
    /// The window between the code being accepted and the token being written.
    /// </summary>
    /// <remarks>
    /// An implementation that re-reads the enrollment after verifying and records
    /// <em>that</em> generation hands the token authority over whatever it finds -
    /// which, if a recovery landed in that window, is the recovered enrollment the
    /// user never proved.
    /// </remarks>
    [Fact]
    public async Task RecoveryBetweenTheCodeAndTheTokenRefusesAuthorisation()
    {
        _h.Seed("victim");
        await _h.Service.PushAsync("victim", Purpose.Replace);
        var code = _h.LastCode;

        // Fire the recovery on the identity read that happens after verify.
        var reads = 0;
        var hooked = new HookedIdentityStore(_h.Identities, async () =>
        {
            if (Interlocked.Increment(ref reads) == 3)
            {
                await _h.Service.UnlinkAfterExternalProofAsync("victim", "support recovery");
                var fresh = await _h.Service.StartDeepLinkAsync("victim");
                await _h.Service.CompleteDeepLinkAsync(fresh.Token, "888000333");
            }
        });

        var service = new TelegramTwoFactorService(
            _h.Config, _h.Store, hooked, _h.Telegram, _h.Messages, _h.Clock);

        var result = await service.StartChatReplacementAsync("victim", code);

        // Either refused outright, or the token it produced is inert. Silently
        // acquiring authority over the recovered enrollment is neither.
        if (result.Ok)
        {
            Assert.False(
                (await _h.Service.CompleteDeepLinkAsync(result.Request!.Token, "999000444")).Ok,
                "a token minted after recovery must not bind");
        }

        Assert.Equal(
            "888000333",
            (await _h.Service.IdentityAsync("victim"))!.ChatId);
    }

    /// <summary>
    /// Preventing a stale record from being written back is best-effort; accepting
    /// one is impossible.
    /// </summary>
    /// <remarks>
    /// So put it back by hand - exactly what a lost race would do - and require that
    /// it still cannot authorise anything.
    /// </remarks>
    [Fact]
    public async Task AStaleRecordIsInertEvenWhenWrittenBack()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        var key = _h.Config.Key("code", "user-1");
        var record = await _h.Store.GetAsync(key);

        await _h.Service.UnlinkAfterExternalProofAsync("user-1", "support recovery");
        var fresh = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(fresh.Token, "888000333");

        // Resurrect it.
        await _h.Store.PutAsync(key, record!, 300);

        Assert.False(
            (await _h.Service.VerifyAsync("user-1", code)).Ok,
            "a record from a superseded enrollment must be inert even if restored");
    }

    [Fact]
    public async Task ReplacementInvalidatesACodeSentToTheOldChat()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Replace);

        var result = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.True(result.Ok);

        ((FrozenClock)_h.Clock).Advance(121);
        await _h.Service.PushAsync("user-1", Purpose.Login);
        var inFlight = _h.LastCode;

        Assert.True((await _h.Service.CompleteDeepLinkAsync(result.Request!.Token, "777000222")).Ok);
        Assert.False((await _h.Service.VerifyAsync("user-1", inFlight, Purpose.Login)).Ok);
    }

    [Fact]
    public async Task ALoginCodeCannotAuthoriseAReplacement()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Login);

        var result = await _h.Service.StartChatReplacementAsync("user-1", _h.LastCode);

        Assert.False(result.Ok);
        Assert.Null(result.Request);
    }

    [Fact]
    public async Task TheGenerationSurvivesUnlinking()
    {
        _h.Seed();

        await _h.Service.UnlinkAfterExternalProofAsync("user-1", "user asked");

        var identity = await _h.Service.IdentityAsync("user-1");

        // The row remains, carrying a new generation and no chat: revocation has to
        // outlive the binding it revoked.
        Assert.NotNull(identity);
        Assert.Null(identity!.ChatId);
        Assert.False(identity.IsVerified);
        Assert.NotEqual("gen-user-1", identity.Generation);
    }

    [Fact]
    public async Task UnlinkingNotifiesTheChatAndClearsPending()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Unlink);
        var code = _h.LastCode;
        _h.Telegram.Reset();

        Assert.True((await _h.Service.UnlinkAsync("user-1", code)).Ok);
        Assert.Single(_h.Telegram.Sent);
        Assert.Contains("unlinked", _h.Telegram.LastMessage.ToLowerInvariant(), StringComparison.Ordinal);
        Assert.Null(await _h.Store.GetAsync(_h.Config.Key("code", "user-1")));
        Assert.Null(await _h.Store.GetAsync(_h.Config.Key("cooldown", "user-1")));
    }
}

/// <summary>
/// Delegates to a real store, running a hook on each read by user id.
/// </summary>
/// <remarks>
/// Targets the window between a code being accepted and a token being minted,
/// which is the third read in that sequence.
/// </remarks>
internal sealed class HookedIdentityStore : IIdentityStore
{
    private readonly IIdentityStore _inner;
    private readonly Func<Task> _onRead;

    internal HookedIdentityStore(IIdentityStore inner, Func<Task> onRead)
    {
        _inner = inner;
        _onRead = onRead;
    }

    public async Task<Identity?> FindByUserIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        await _onRead().ConfigureAwait(false);

        return await _inner.FindByUserIdAsync(userId, cancellationToken).ConfigureAwait(false);
    }

    public Task<Identity?> FindByChatIdAsync(string chatId, CancellationToken cancellationToken = default) =>
        _inner.FindByChatIdAsync(chatId, cancellationToken);

    public Task<Identity?> TransitionAsync(
        string userId,
        string? chatId,
        string? expected,
        string nextGeneration,
        CancellationToken cancellationToken = default) =>
        _inner.TransitionAsync(userId, chatId, expected, nextGeneration, cancellationToken);
}
