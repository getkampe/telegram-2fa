using Kampe.TelegramTwoFactor.Stores;
using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>
/// SPEC.md 5.1 - the state transitions that must be atomic.
/// </summary>
/// <remarks>
/// These use real threads against the shipped stores, released together by a
/// barrier. The <see cref="YieldingClock"/> is what makes the suite
/// <em>sensitive</em>: without it these tests pass against a store with no lock at
/// all, because a critical section this short normally completes before the
/// scheduler preempts it - the same false confidence the Python port's first
/// threaded suite gave.
/// </remarks>
public class MemoryStoreConcurrencyTests
{
    /// <summary>The sensitivity check for everything else in this class.</summary>
    [Fact]
    public async Task AMissingLockWouldBeCaught()
    {
        var store = new MemoryCodeStore(new YieldingClock());
        await store.PutAsync("k", "\"value\"", 60);

        var results = TestSupport.Race(8, _ => store.TakeAsync("k"));

        Assert.True(
            results.Count(r => r is not null) == 1,
            "exactly one caller may receive the value, even when the critical section is forced to yield");
    }

    [Fact]
    public void AddIsAtomicWhenForcedToYield()
    {
        var store = new MemoryCodeStore(new YieldingClock());

        var results = TestSupport.Race(8, i => store.AddAsync("k", $"\"{i}\"", 60));

        Assert.True(results.Count(won => won) == 1, "exactly one reservation may win");
    }

    [Fact]
    public async Task OnlyOneOfManyConcurrentTakesGetsTheValue()
    {
        var store = new MemoryCodeStore(new FrozenClock());
        await store.PutAsync("k", "\"value\"", 60);

        var results = TestSupport.Race(16, _ => store.TakeAsync("k"));

        Assert.Equal(new[] { "\"value\"" }, results.Where(r => r is not null).ToArray());
    }

    [Fact]
    public async Task AReservationLoserDoesNotOverwriteTheWinner()
    {
        var store = new MemoryCodeStore(new FrozenClock());
        await store.AddAsync("k", "\"first\"", 60);

        TestSupport.Race(8, i => store.AddAsync("k", $"\"other-{i}\"", 60));

        Assert.Equal("\"first\"", await store.GetAsync("k"));
    }
}

public class IdentityStoreConcurrencyTests
{
    [Fact]
    public async Task OnlyOneOfManyConcurrentTransitionsApplies()
    {
        var identities = new MemoryIdentityStore(new YieldingClock());

        var results = TestSupport.Race(
            8,
            i => identities.TransitionAsync("u", $"chat-{i}", null, $"gen-{i}"));

        var applied = results.Where(r => r is not null).ToArray();

        Assert.True(applied.Length == 1, "all started from the same expectation, so one may apply");

        // And the stored row is the winner's, not a mixture.
        var stored = await identities.FindByUserIdAsync("u");

        Assert.Equal(applied[0]!.ChatId, stored!.ChatId);
        Assert.Equal(applied[0]!.Generation, stored.Generation);
    }

    [Fact]
    public void OneChatCannotBeClaimedByTwoAccountsConcurrently()
    {
        var identities = new MemoryIdentityStore(new YieldingClock());

        var outcomes = TestSupport.RaceTolerantly(
            8,
            i => identities.TransitionAsync($"user-{i}", "shared", null, $"gen-{i}"));

        var won = outcomes.Count(o => o.Failure is null && o.Result is not null);
        var refused = outcomes.Count(o => o.Failure is ChatAlreadyLinkedException);

        Assert.Equal(1, won);
        Assert.Equal(7, refused);
    }
}

/// <summary>
/// Whether the service consumes a challenge in one store operation.
/// </summary>
/// <remarks>
/// Splitting it into a read and a delete is the oldest way to break single use,
/// and it is invisible to the suites above: a clock cannot open that window,
/// because a pause inside a critical section is harmless and the thread that
/// released a lock can re-acquire it before a woken waiter is scheduled.
/// </remarks>
public class AtomicConsumptionTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task AVerificationConsumesTheRecordInASingleOperation()
    {
        var recorder = new RecordingStore(_h.Store, 0);
        var service = _h.WithStore(recorder);
        _h.Seed();
        await service.PushAsync("user-1");
        recorder.ResetCalls();

        Assert.True((await service.VerifyAsync("user-1", _h.LastCode)).Ok);

        // Anything longer is a read-modify-write with a gap in it.
        Assert.Equal(
            new[] { "take" },
            recorder.Calls.ToArray());
    }

    [Fact]
    public async Task OnlyOneVerificationWinsWhenTheStoreYieldsBetweenCalls()
    {
        var service = _h.WithStore(new RecordingStore(_h.Store));
        _h.Seed();
        await service.PushAsync("user-1");
        var code = _h.LastCode;

        var results = TestSupport.Race(8, _ => service.VerifyAsync("user-1", code));

        Assert.True(
            results.Count(r => r.Ok) == 1,
            "with the gap between store calls held open, only an atomic take keeps a code single-use");
    }

    [Fact]
    public void OnlyOneChallengeIsIssuedWhenTheStoreYieldsBetweenCalls()
    {
        var service = _h.WithStore(new RecordingStore(_h.Store));
        _h.Seed();

        var results = TestSupport.Race(8, _ => service.PushAsync("user-1"));

        Assert.True(results.Count(r => r.Ok) == 1, "the cooldown must be a reservation, not a check");
        Assert.Single(_h.Telegram.Sent);
    }
}

/// <summary>The same properties, through a store whose critical sections interleave.</summary>
public class ServiceOnYieldingStoreTests
{
    private readonly Harness _h = new(new YieldingClock());

    [Fact]
    public async Task ExactlyOneOfManyConcurrentVerificationsSucceeds()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        var results = TestSupport.Race(12, _ => _h.Service.VerifyAsync("user-1", code));

        Assert.True(
            results.Count(r => r.Ok) == 1,
            "a single-use code must authorise exactly one action");
    }

    [Fact]
    public void ManyConcurrentChallengesSendOneCode()
    {
        _h.Seed();

        var results = TestSupport.Race(8, _ => _h.Service.PushAsync("user-1"));

        Assert.Single(results, r => r.Ok);
        Assert.Single(_h.Telegram.Sent);
    }

    [Fact]
    public async Task OneLinkTokenBindsOneChat()
    {
        var request = await _h.Service.StartDeepLinkAsync("user-1");

        var results = TestSupport.Race(
            8,
            i => _h.Service.CompleteDeepLinkAsync(request.Token, $"chat-{i}"));

        Assert.True(results.Count(r => r.Ok) == 1, "a link token must bind exactly one chat");
    }
}

/// <summary>The properties an application actually depends on.</summary>
public class ServiceConcurrencyTests
{
    private readonly Harness _h = new();

    [Fact]
    public async Task ExactlyOneOfManyConcurrentVerificationsSucceeds()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;

        var results = TestSupport.Race(16, _ => _h.Service.VerifyAsync("user-1", code));

        Assert.Single(results, r => r.Ok);
    }

    /// <summary>
    /// "Concurrent failures preserve the attempt budget" means no increment is lost -
    /// not that sixteen parallel guesses spend sixteen attempts.
    /// </summary>
    /// <remarks>
    /// With an atomic take only the holder's guess is compared at all; the rest are
    /// told expired without being evaluated, and a guess that is never evaluated
    /// cannot be a hit. The property that must hold is that the number of guesses
    /// actually compared never exceeds the budget, however many threads are thrown at
    /// it.
    /// </remarks>
    [Fact]
    public async Task ParallelismCannotWinMoreGuessesThanTheBudget()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var wrong = TestSupport.WrongCode(_h.LastCode);

        var results = TestSupport.Race(16, _ => _h.Service.VerifyAsync("user-1", wrong));
        var evaluated = results.Count(r => r.Error == ErrorCode.Invalid);

        Assert.True(evaluated >= 1, "at least one guess must be checked");
        Assert.True(
            evaluated <= _h.Config.MaxAttempts,
            "parallelism must not buy more comparisons than the budget allows");
    }

    [Fact]
    public async Task TheBudgetStillEndsTheCodeInSequence()
    {
        _h.Seed();
        await _h.Service.PushAsync("user-1");
        var code = _h.LastCode;
        var wrong = TestSupport.WrongCode(code);

        for (var i = 0; i < _h.Config.MaxAttempts; i++)
        {
            await _h.Service.VerifyAsync("user-1", wrong);
        }

        Assert.False((await _h.Service.VerifyAsync("user-1", code)).Ok, "five wrong guesses must kill the code");
    }

    [Fact]
    public void ManyConcurrentChallengesSendOneCode()
    {
        _h.Seed();

        var results = TestSupport.Race(8, _ => _h.Service.PushAsync("user-1"));

        Assert.Single(results, r => r.Ok);
        Assert.Single(_h.Telegram.Sent);
    }

    [Fact]
    public async Task ConcurrentOrdinaryLinksCannotReplaceEachOther()
    {
        var tokens = new string[8];

        for (var i = 0; i < tokens.Length; i++)
        {
            tokens[i] = (await _h.Service.StartDeepLinkAsync("user-1")).Token;
        }

        var results = TestSupport.Race(
            8,
            i => _h.Service.CompleteDeepLinkAsync(tokens[i], $"chat-{i}"));

        Assert.Single(results, r => r.Ok);

        var identity = await _h.Service.IdentityAsync("user-1");

        Assert.NotNull(identity);
        Assert.Equal(
            identity!.UserId,
            (await _h.Service.IdentityForChatAsync(identity.ChatId!))!.UserId);
    }
}
