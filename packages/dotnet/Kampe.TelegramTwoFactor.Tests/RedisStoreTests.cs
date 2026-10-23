using Kampe.TelegramTwoFactor.Stores;
using Kampe.TelegramTwoFactor.Telegram;
using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>
/// A Redis stand-in: enough of the protocol for the store, and nothing more.
/// </summary>
/// <remarks>
/// Its own semantics are the point of the exercise - SET NX refusing, GETDEL
/// returning and removing in one call - so the store is checked against the
/// behaviour the real server has rather than against a mock of itself.
/// </remarks>
public class FakeRedis : IRedisCommands
{
    private readonly Dictionary<string, string> _items = new(StringComparer.Ordinal);
    private readonly List<string> _calls = new();

    public IReadOnlyList<string> Calls => _calls.ToArray();

    public IReadOnlyCollection<string> Keys => _items.Keys.ToArray();

    public void ClearCalls() => _calls.Clear();

    public string? Raw(string key) => _items.TryGetValue(key, out var value) ? value : null;

    public void SetRaw(string key, string value) => _items[key] = value;

    public Task<string?> GetAsync(string key, CancellationToken cancellationToken)
    {
        _calls.Add("GET");

        return Task.FromResult(Raw(key));
    }

    public Task DeleteAsync(string key, CancellationToken cancellationToken)
    {
        _calls.Add("DEL");
        _items.Remove(key);

        return Task.CompletedTask;
    }

    public Task<bool> SetAsync(
        string key,
        string value,
        int ttlSeconds,
        bool onlyIfAbsent,
        CancellationToken cancellationToken)
    {
        _calls.Add(onlyIfAbsent ? $"SET NX {ttlSeconds}" : $"SET {ttlSeconds}");

        if (onlyIfAbsent && _items.ContainsKey(key))
        {
            return Task.FromResult(false);
        }

        _items[key] = value;

        return Task.FromResult(true);
    }

    public virtual Task<string?> GetDeleteAsync(string key, CancellationToken cancellationToken)
    {
        _calls.Add("GETDEL");

        var value = Raw(key);
        _items.Remove(key);

        return Task.FromResult(value);
    }
}

public class RedisStoreTests
{
    private readonly FakeRedis _redis = new();
    private readonly RedisCodeStore _store;

    public RedisStoreTests() => _store = new RedisCodeStore(_redis);

    [Fact]
    public async Task ARecordRoundTrips()
    {
        await _store.PutAsync("k", """{"hash":"abc","attempts":0}""", 300);

        Assert.Equal("""{"hash":"abc","attempts":0}""", await _store.GetAsync("k"));
    }

    [Fact]
    public async Task TheTtlIsPassedToTheServer()
    {
        await _store.PutAsync("k", "\"v\"", 300);

        Assert.Contains("SET 300", _redis.Calls);
    }

    [Fact]
    public async Task AMissingKeyReadsAsNull() => Assert.Null(await _store.GetAsync("absent"));

    [Fact]
    public async Task TakeRemovesTheKeyAndReturnsTheValue()
    {
        await _store.PutAsync("k", "\"v\"", 300);

        Assert.Equal("\"v\"", await _store.TakeAsync("k"));
        Assert.Null(await _store.GetAsync("k"));
    }

    /// <summary>
    /// The one property the whole single-use guarantee rests on: the value leaves
    /// the server in the same operation that returns it.
    /// </summary>
    [Fact]
    public async Task TakeIsOneServerOperation()
    {
        await _store.PutAsync("k", "\"v\"", 300);
        _redis.ClearCalls();

        await _store.TakeAsync("k");

        Assert.Equal(
            new[] { "GETDEL" },
            _redis.Calls.ToArray());
    }

    [Fact]
    public async Task AddReservesAnAbsentKey()
    {
        Assert.True(await _store.AddAsync("k", "\"first\"", 60));
        Assert.Equal("\"first\"", await _store.GetAsync("k"));
    }

    [Fact]
    public async Task AddRefusesAnOccupiedKeyAndLeavesItAlone()
    {
        await _store.AddAsync("k", "\"first\"", 60);

        Assert.False(await _store.AddAsync("k", "\"second\"", 60));
        Assert.Equal("\"first\"", await _store.GetAsync("k"));
    }

    [Fact]
    public async Task AddUsesSetNx()
    {
        await _store.AddAsync("k", "\"first\"", 60);

        Assert.Contains("SET NX 60", _redis.Calls);
    }

    [Fact]
    public async Task ForgetRemovesTheKey()
    {
        await _store.PutAsync("k", "\"v\"", 60);
        await _store.ForgetAsync("k");

        Assert.Empty(_redis.Keys);
    }
}

/// <summary>
/// The store is only useful if the service works through it, so run the protocol
/// over it rather than asserting on keys.
/// </summary>
public class ServiceOnRedisTests
{
    private readonly FrozenClock _clock = new();
    private readonly FakeRedis _redis = new();
    private readonly FakeTelegram _telegram = new();
    private readonly MemoryIdentityStore _identities;
    private readonly TelegramTwoFactorService _service;

    public ServiceOnRedisTests()
    {
        _identities = new MemoryIdentityStore(_clock);

        _service = new TelegramTwoFactorService(
            TestSupport.MakeConfig(),
            new RedisCodeStore(_redis),
            _identities,
            _telegram,
            new DefaultMessages(),
            _clock);

        _identities.Seed("user-1", "555000111", "gen-user-1");
    }

    private string Code => TestSupport.CodeFrom(_telegram.LastMessage);

    [Fact]
    public async Task ACodeIsIssuedAndVerifiedThroughTheRedisStore()
    {
        Assert.True((await _service.PushAsync("user-1")).Ok);
        Assert.True((await _service.VerifyAsync("user-1", Code)).Ok);
    }

    [Fact]
    public async Task ACodeIsSingleUseThroughTheRedisStore()
    {
        await _service.PushAsync("user-1");
        var issued = Code;

        Assert.True((await _service.VerifyAsync("user-1", issued)).Ok);
        Assert.Equal(ErrorCode.Expired, (await _service.VerifyAsync("user-1", issued)).Error);
    }

    [Fact]
    public async Task TheAttemptCounterSurvivesTheJsonRoundTrip()
    {
        await _service.PushAsync("user-1");
        var wrong = TestSupport.WrongCode(Code);

        Assert.Equal(4, (await _service.VerifyAsync("user-1", wrong)).AttemptsRemaining);
        Assert.Equal(3, (await _service.VerifyAsync("user-1", wrong)).AttemptsRemaining);
    }

    [Fact]
    public async Task TheCooldownWorksThroughTheRedisStore()
    {
        await _service.PushAsync("user-1");

        Assert.Equal(ErrorCode.Cooldown, (await _service.PushAsync("user-1")).Error);
    }

    [Fact]
    public async Task TheDeeplinkFlowWorksThroughTheRedisStore()
    {
        var request = await _service.StartDeepLinkAsync("user-2");

        Assert.True((await _service.CompleteDeepLinkAsync(request.Token, "777000222")).Ok);
        Assert.Equal(
            ErrorCode.InvalidToken,
            (await _service.CompleteDeepLinkAsync(request.Token, "888000333")).Error);
    }

    /// <summary>
    /// A key holding something this library did not write - a collision with another
    /// application's prefix - must not throw from inside a verification path.
    /// </summary>
    [Fact]
    public async Task ANonJsonValueUnderOurKeyReadsAsAbsent()
    {
        _redis.SetRaw(TestSupport.MakeConfig().Key("code", "user-1"), "not json at all");

        Assert.Equal(ErrorCode.Expired, (await _service.VerifyAsync("user-1", "123456")).Error);
    }
}
