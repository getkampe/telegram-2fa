using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>SPEC.md sections 4, 5 and 6 - challenge, verification, purpose.</summary>
public class ChallengeTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task PushSendsACodeToTheLinkedChat()
    {
        _h.Seed();

        var result = await _h.Service.PushAsync("user-1");

        Assert.True(result.Ok);
        Assert.Single(_h.Telegram.Sent);
        Assert.Equal("555000111", _h.Telegram.Sent[0].ChatId);
        Assert.Matches("^[0-9]{6}$", _h.LastCode);
    }

    [Fact]
    public async Task PushRefusesAnUnlinkedAccount()
    {
        Assert.Equal(ErrorCode.NotLinked, (await _h.Service.PushAsync("nobody")).Error);
        Assert.Empty(_h.Telegram.Sent);
    }

    [Fact]
    public async Task AnUnverifiedLinkIsNotASecondFactor()
    {
        // A chat id with no verification timestamp: a link started and never
        // finished.
        await _h.Identities.TransitionAsync("user-1", null, null, "gen-partial");

        Assert.Equal(ErrorCode.NotLinked, (await _h.Service.PushAsync("user-1")).Error);
    }

    [Fact]
    public async Task TheCodeNeverAppearsInTheResult()
    {
        _h.Seed();

        var result = await _h.Service.PushAsync("user-1");

        // The result routinely goes straight into an HTTP response, so assert on its
        // serialised form rather than its properties.
        var serialised = System.Text.Json.JsonSerializer.Serialize(result);

        Assert.DoesNotContain(_h.LastCode, serialised, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASecondRequestInsideTheCooldownIsRefused()
    {
        _h.Seed();

        await _h.Service.PushAsync("user-1");
        var second = await _h.Service.PushAsync("user-1");

        Assert.Equal(ErrorCode.Cooldown, second.Error);
        Assert.Equal(120, second.RetryAfter(_h.Clock.Now));
        Assert.Single(_h.Telegram.Sent);
    }

    [Fact]
    public async Task ARequestAfterTheCooldownIsAllowed()
    {
        _h.Seed();

        await _h.Service.PushAsync("user-1");
        ((FrozenClock)_h.Clock).Advance(121);

        Assert.True((await _h.Service.PushAsync("user-1")).Ok);
        Assert.Equal(2, _h.Telegram.Sent.Count);
    }

    [Fact]
    public async Task AFailedDeliveryLeavesNoLiveCodeAndNoCooldown()
    {
        _h.Seed();
        _h.Telegram.ShouldFailSending = true;

        Assert.Equal(ErrorCode.SendFailed, (await _h.Service.PushAsync("user-1")).Error);

        // A code the user never received must not occupy the slot, or the account is
        // stuck until the cooldown expires with no way to try again.
        _h.Telegram.ShouldFailSending = false;

        Assert.True((await _h.Service.PushAsync("user-1")).Ok);
    }

    [Fact]
    public async Task ALateDeliveryFailureCannotDiscardANewerChallenge()
    {
        _h.Seed();

        _h.Telegram.FailNextSend(async () =>
        {
            ((FrozenClock)_h.Clock).Advance(121);
            await _h.Service.PushAsync("user-1", Purpose.Login);
        });

        Assert.Equal(ErrorCode.SendFailed, (await _h.Service.PushAsync("user-1", Purpose.Login)).Error);

        Assert.True(
            (await _h.Service.VerifyAsync("user-1", _h.LastCode, Purpose.Login)).Ok,
            "the cleanup for a failed send must only discard its own challenge");
    }

    [Fact]
    public async Task PullIssuesACodeForAKnownChat()
    {
        _h.Seed();

        Assert.True((await _h.Service.PullAsync("555000111")).Ok);
        Assert.Matches("^[0-9]{6}$", _h.LastCode);
    }

    [Fact]
    public async Task PullRefusesAnUnknownChat() =>
        Assert.Equal(ErrorCode.NotLinked, (await _h.Service.PullAsync("404404404")).Error);

    /// <summary>
    /// The single-key rule of SPEC.md section 4.
    /// </summary>
    /// <remarks>
    /// An implementation that writes one key on push and reads another passes every
    /// pull-path test and silently fails every real push.
    /// </remarks>
    [Fact]
    public async Task APushedAndAPulledCodeVerifyThroughTheSameCall()
    {
        _h.Seed();

        await _h.Service.PushAsync("user-1");

        Assert.True((await _h.Service.VerifyAsync("user-1", _h.LastCode)).Ok);

        ((FrozenClock)_h.Clock).Advance(121);
        await _h.Service.PullAsync("555000111");

        Assert.True((await _h.Service.VerifyAsync("user-1", _h.LastCode)).Ok);
    }

    [Fact]
    public async Task CodesAreStoredHashedRatherThanInPlaintext()
    {
        _h.Seed();

        await _h.Service.PushAsync("user-1");
        var raw = await _h.Store.GetAsync(_h.Config.Key("code", "user-1"));

        Assert.NotNull(raw);
        Assert.DoesNotContain(_h.LastCode, raw!, StringComparison.Ordinal);
        Assert.Contains("\"hash\"", raw!, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two accounts share a generation on purpose.
    /// </summary>
    /// <remarks>
    /// With different ones the enrollment check in Verify refuses the transplanted
    /// record before the digest is ever compared, so the test would pass against a
    /// hasher that ignored the account entirely.
    /// </remarks>
    [Fact]
    public async Task ADigestDoesNotVerifyAgainstADifferentAccount()
    {
        _h.Identities.Seed("user-1", "555000111", "shared-generation");
        _h.Identities.Seed("user-2", "777000222", "shared-generation");

        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;
        var record = await _h.Store.GetAsync(_h.Config.Key("code", "user-1"));

        // Transplant it, as a store-level attacker holding a known code would.
        await _h.Store.PutAsync(_h.Config.Key("code", "user-2"), record!, 300);

        Assert.False(
            (await _h.Service.VerifyAsync("user-2", code)).Ok,
            "the digest is keyed to the account, so only that account's code matches it");
        Assert.True((await _h.Service.VerifyAsync("user-1", code)).Ok);
    }
}

public class VerificationTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task TheRightCodePasses()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");

        Assert.True((await _h.Service.VerifyAsync("user-1", _h.LastCode)).Ok);
    }

    [Fact]
    public async Task AWrongCodeFailsAndSpendsAnAttempt()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");

        var result = await _h.Service.VerifyAsync("user-1", TestSupport.WrongCode(_h.LastCode));

        Assert.Equal(ErrorCode.Invalid, result.Error);
        Assert.Equal(4, result.AttemptsRemaining);
    }

    [Fact]
    public async Task ACodeWorksOnlyOnce()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        Assert.True((await _h.Service.VerifyAsync("user-1", code)).Ok);

        var replay = await _h.Service.VerifyAsync("user-1", code);

        Assert.False(replay.Ok);
        Assert.Equal(ErrorCode.Expired, replay.Error);
    }

    [Fact]
    public async Task TheAttemptBudgetKillsTheCode()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;
        var wrong = TestSupport.WrongCode(code);

        for (var i = 0; i < 4; i++)
        {
            Assert.Equal(ErrorCode.Invalid, (await _h.Service.VerifyAsync("user-1", wrong)).Error);
        }

        Assert.Equal(ErrorCode.TooManyAttempts, (await _h.Service.VerifyAsync("user-1", wrong)).Error);

        // And the real code is dead too: the budget belongs to the code, not to the
        // attacker.
        Assert.False((await _h.Service.VerifyAsync("user-1", code)).Ok);
    }

    [Fact]
    public async Task AnExpiredCodeFails()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        ((FrozenClock)_h.Clock).Advance(301);

        Assert.Equal(ErrorCode.Expired, (await _h.Service.VerifyAsync("user-1", code)).Error);
    }

    [Fact]
    public async Task AWrongGuessDoesNotExtendTheCodesLife()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        ((FrozenClock)_h.Clock).Advance(200);
        await _h.Service.VerifyAsync("user-1", TestSupport.WrongCode(code));

        ((FrozenClock)_h.Clock).Advance(101); // 301s since issue

        Assert.Equal(ErrorCode.Expired, (await _h.Service.VerifyAsync("user-1", code)).Error);
    }

    [Fact]
    public async Task WhitespaceAroundAPastedCodeIsTolerated()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");

        Assert.True((await _h.Service.VerifyAsync("user-1", $" {_h.LastCode}\n")).Ok);
    }

    [Fact]
    public async Task AUserIdIsTreatedAsAnOpaqueString()
    {
        const string uuid = "9b7c2f0e-4d5a-4c21-8f3b-1a2b3c4d5e6f";
        _h.Identities.Seed(uuid, "555000111", "gen-uuid");

        Assert.True((await _h.Service.PushAsync(uuid)).Ok);
        Assert.True((await _h.Service.VerifyAsync(uuid, _h.LastCode)).Ok);
    }
}

public class PurposeTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task APushedCodeDoesNotSatisfyAnotherPurpose()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Login);

        Assert.False((await _h.Service.VerifyAsync("user-1", _h.LastCode, "withdrawal")).Ok);
    }

    [Fact]
    public async Task OmittingThePurposeMeansLoginNotAWildcard()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", "withdrawal");

        Assert.False((await _h.Service.VerifyAsync("user-1", _h.LastCode)).Ok);
    }

    [Fact]
    public async Task AnOnDemandCodeSatisfiesAnyPurpose()
    {
        _h.Seed();
        await _h.Service.PullAsync("555000111");

        Assert.True((await _h.Service.VerifyAsync("user-1", _h.LastCode, "withdrawal")).Ok);
    }

    [Fact]
    public async Task APurposeMismatchReportsInvalidAndSpendsAnAttempt()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Login);
        var code = _h.LastCode;

        var first = await _h.Service.VerifyAsync("user-1", code, "withdrawal");

        // Reporting the mismatch distinctly would tell a caller that a live code
        // exists for a different step, which it has not proved it may know.
        Assert.Equal(ErrorCode.Invalid, first.Error);
        Assert.Equal(4, first.AttemptsRemaining);
        Assert.Equal(3, (await _h.Service.VerifyAsync("user-1", code, "withdrawal")).AttemptsRemaining);
    }

    [Fact]
    public async Task UnlinkingRejectsACodePushedForALogin()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1", Purpose.Login);

        Assert.False((await _h.Service.UnlinkAsync("user-1", _h.LastCode)).Ok);
        Assert.True(await _h.Service.IsLinkedAsync("user-1"));
    }

    [Fact]
    public async Task UnlinkingAcceptsACodeTheUserFetched()
    {
        _h.Seed();
        await _h.Service.PullAsync("555000111");

        Assert.True((await _h.Service.UnlinkAsync("user-1", _h.LastCode)).Ok);
        Assert.False(await _h.Service.IsLinkedAsync("user-1"));
    }

    [Fact]
    public async Task TheOnDemandExemptionCanBeNarrowed()
    {
        var narrowed = _h.WithConfig(TestSupport.MakeConfig(onDemandSatisfies: new[] { "login" }));
        _h.Seed();

        await narrowed.PullAsync("555000111");

        Assert.True((await narrowed.VerifyAsync("user-1", _h.LastCode, "login")).Ok);

        ((FrozenClock)_h.Clock).Advance(121);
        await narrowed.PullAsync("555000111");

        Assert.False((await narrowed.VerifyAsync("user-1", _h.LastCode, "withdrawal")).Ok);
    }
}

/// <summary>SPEC.md sections 2 and 3 - linking.</summary>
public class LinkingTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task TheDeeplinkFlowLinksTheAccount()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");

        Assert.Equal($"https://t.me/kampe_test_bot?start={request.Token}", request.Url);
        Assert.True((await _h.Service.CompleteDeepLinkAsync(request.Token, "555000111")).Ok);
        Assert.True(await _h.Service.IsLinkedAsync("user-1"));
    }

    [Fact]
    public async Task ADeeplinkTokenIsSingleUse()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(request.Token, "555000111");

        // A second presentation from a different chat: the obvious attack if the token
        // survives, since the token travels through a chat message.
        var replay = await _h.Service.CompleteDeepLinkAsync(request.Token, "999999999");

        Assert.Equal(ErrorCode.InvalidToken, replay.Error);
    }

    [Fact]
    public async Task AnExpiredDeeplinkTokenIsRefused()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");
        ((FrozenClock)_h.Clock).Advance(601);

        Assert.Equal(
            ErrorCode.InvalidToken,
            (await _h.Service.CompleteDeepLinkAsync(request.Token, "555000111")).Error);
    }

    [Fact]
    public async Task TheLinkTokenIsNotStoredInPlaintext()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");

        Assert.Null(await _h.Store.GetAsync(_h.Config.Key("link", request.Token)));
        Assert.True((await _h.Service.CompleteDeepLinkAsync(request.Token, "555000111")).Ok);
    }

    [Fact]
    public async Task ThePasteFlowLinksTheAccount()
    {
        var request = await _h.Service.StartPasteLinkAsync("555000111");

        // The paste flow's key is derived from the code, so all outstanding codes
        // share one namespace. Eight base32 characters is 40 bits.
        Assert.Equal(8, request.Token.Length);
        Assert.Matches($"^[{CodeGenerator.LinkAlphabet}]{{8}}$", request.Token);

        Assert.True((await _h.Service.CompletePasteLinkAsync("user-1", request.Token)).Ok);
        Assert.True(await _h.Service.IsLinkedAsync("user-1"));
    }

    [Fact]
    public async Task APasteCodeIsAcceptedInLowerCase()
    {
        var request = await _h.Service.StartPasteLinkAsync("555000111");

        Assert.True((await _h.Service.CompletePasteLinkAsync("user-1", request.Token.ToLowerInvariant())).Ok);
    }

    /// <summary>
    /// One Telegram account as the factor for several accounts means one compromised
    /// Telegram account compromises all of them.
    /// </summary>
    [Fact]
    public async Task AChatCannotBecomeTheFactorForASecondAccount()
    {
        var first = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(first.Token, "555000111");

        var second = await _h.Service.StartDeepLinkAsync("user-2");

        Assert.Equal(
            ErrorCode.AlreadyLinked,
            (await _h.Service.CompleteDeepLinkAsync(second.Token, "555000111")).Error);
        Assert.False(await _h.Service.IsLinkedAsync("user-2"));
        Assert.Equal("user-1", (await _h.Service.IdentityForChatAsync("555000111"))!.UserId);
    }

    [Fact]
    public async Task AnAccountCannotBeMovedWithoutAReplacement()
    {
        var first = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(first.Token, "555000111");

        var second = await _h.Service.StartDeepLinkAsync("user-1");

        Assert.Equal(
            ErrorCode.AlreadyLinked,
            (await _h.Service.CompleteDeepLinkAsync(second.Token, "777000222")).Error);
        Assert.Equal("555000111", (await _h.Service.IdentityAsync("user-1"))!.ChatId);
    }

    [Fact]
    public async Task RelinkingTheSameChatIsIdempotent()
    {
        var first = await _h.Service.StartDeepLinkAsync("user-1");
        await _h.Service.CompleteDeepLinkAsync(first.Token, "555000111");

        // A user who taps the same link twice, or whose first confirmation was lost,
        // should see success rather than a conflict.
        var second = await _h.Service.StartDeepLinkAsync("user-1");

        Assert.True((await _h.Service.CompleteDeepLinkAsync(second.Token, "555000111")).Ok);
    }
}
