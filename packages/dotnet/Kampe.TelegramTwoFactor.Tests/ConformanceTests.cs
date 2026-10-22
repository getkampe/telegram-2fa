using System.Text.Json;
using Kampe.TelegramTwoFactor.Stores;
using Kampe.TelegramTwoFactor.Telegram;
using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>
/// SPEC.md section 9, against the shared fixture in /conformance.
/// </summary>
/// <remarks>
/// The repository claims the implementations can share one bot and one store. That
/// is a claim about field names and hash construction, and it only means anything
/// if every implementation reads the same committed records.
/// </remarks>
public class ConformanceTests
{
    private static readonly JsonDocument Fixture = JsonDocument.Parse(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "conformance", "records.json")));

    private readonly FrozenClock _clock;
    private readonly MemoryCodeStore _store;
    private readonly MemoryIdentityStore _identities;
    private readonly Config _config;
    private readonly TelegramTwoFactorService _service;

    public ConformanceTests()
    {
        var root = Fixture.RootElement;
        var config = root.GetProperty("config");

        _clock = new FrozenClock(root.GetProperty("now").GetInt64());
        _store = new MemoryCodeStore(_clock);
        _identities = new MemoryIdentityStore(_clock);
        _config = TestSupport.MakeConfig(
            keyPrefix: config.GetProperty("key_prefix").GetString()!,
            hashAlgorithm: config.GetProperty("hash_algorithm").GetString()!,
            hashPepper: config.GetProperty("hash_pepper").GetString()!);

        _service = new TelegramTwoFactorService(
            _config, _store, _identities, new FakeTelegram(), new DefaultMessages(), _clock);
    }

    private static JsonElement Record(string name) => Fixture.RootElement.GetProperty(name);

    private static string Text(JsonElement element, string property) =>
        element.GetProperty(property).GetString()!;

    private static string Value(JsonElement element) =>
        element.GetProperty("value").GetRawText();

    [Fact]
    public async Task AChallengeRecordWrittenElsewhereVerifiesHere()
    {
        var record = Record("code_record");

        // Seed the exact enrollment the fixture's challenge belongs to: a challenge
        // from a superseded enrollment is refused, so interop depends on agreeing
        // about that field too.
        _identities.Seed(Text(record, "user_id"), "555000111", Text(record, "enrollment"));
        await _store.PutAsync(Text(record, "key"), Value(record), 300);

        var result = await _service.VerifyAsync(
            Text(record, "user_id"), Text(record, "plaintext_code"), "withdrawal");

        Assert.True(result.Ok, "a record in the shared wire format must verify through the public API");
    }

    [Fact]
    public async Task AChallengeRecordWrittenHereMatchesTheWireFormat()
    {
        _identities.Seed("user-1", "555000111", "gen-local");
        await _service.PushAsync("user-1", "withdrawal");

        var written = await _store.GetAsync(Record("code_record").GetProperty("key").GetString()!);

        Assert.NotNull(written);

        var expected = Record("code_record").GetProperty("value").EnumerateObject()
            .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var actual = JsonDocument.Parse(written!).RootElement.EnumerateObject()
            .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();

        // Field names are the wire format of SPEC.md section 9.
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task AnOnDemandRecordFromElsewhereIsGeneralPurpose()
    {
        var record = Record("on_demand_record");
        _identities.Seed(Text(record, "user_id"), "777000222", Text(record, "enrollment"));
        await _store.PutAsync(Text(record, "key"), Value(record), 300);

        Assert.True(
            (await _service.VerifyAsync(Text(record, "user_id"), Text(record, "plaintext_code"), "login")).Ok);
    }

    [Fact]
    public async Task ADeeplinkRecordWrittenElsewhereResolvesHere()
    {
        var record = Record("deeplink_record");
        await _store.PutAsync(Text(record, "key"), Value(record), 600);

        Assert.True((await _service.CompleteDeepLinkAsync(Text(record, "token"), "888000333")).Ok);
        Assert.Equal("888000333", (await _service.IdentityAsync(Text(record, "user_id")))!.ChatId);
    }

    [Fact]
    public async Task ADeeplinkRecordWrittenHereMatchesTheWireFormat()
    {
        var request = await _service.StartDeepLinkAsync("user-3");
        var hasher = new CodeHasher(_config.HashAlgorithm, _config.HashPepper);
        var written = await _store.GetAsync(_config.Key("link", hasher.Hash(request.Token)));

        Assert.NotNull(written);

        var expected = Record("deeplink_record").GetProperty("value").EnumerateObject()
            .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        var actual = JsonDocument.Parse(written!).RootElement.EnumerateObject()
            .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();

        // An ordinary token carries exactly two fields: the replace mark and the
        // generation belong only to a replacement token, and writing them as nulls
        // would be a different record from the one the other suites read.
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task APasteRecordWrittenElsewhereResolvesHere()
    {
        var record = Record("paste_record");
        await _store.PutAsync(Text(record, "key"), Value(record), 600);

        Assert.True((await _service.CompletePasteLinkAsync("user-9", Text(record, "token"))).Ok);
        Assert.Equal(Text(record, "chat_id"), (await _service.IdentityAsync("user-9"))!.ChatId);
    }

    [Fact]
    public async Task TheCooldownRecordIsABareInteger()
    {
        _identities.Seed("user-1", "555000111", "gen-local");
        await _service.PushAsync("user-1");

        var written = await _store.GetAsync(Record("cooldown_record").GetProperty("key").GetString()!);

        // Not an object: the other implementations read this as a number.
        Assert.NotNull(written);
        Assert.Equal(
            Record("cooldown_record").GetProperty("value").GetInt64(),
            long.Parse(written!, System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// A store may hand back a quoted number rather than a bare one.
    /// </summary>
    /// <remarks>
    /// Laravel's Redis cache leaves bare numerics unserialised so INCR still works
    /// on them, and some drivers stringify every scalar. Refusing to read that would
    /// mean lifting the cooldown.
    /// </remarks>
    [Fact]
    public async Task ACooldownStoredAsAQuotedNumberIsStillUnderstood()
    {
        _identities.Seed("user-1", "555000111", "gen-local");
        await _service.PushAsync("user-1");

        var key = _config.Key("cooldown", "user-1");
        var held = await _store.GetAsync(key);
        await _store.PutAsync(key, $"\"{held}\"", 120);

        var result = await _service.PushAsync("user-1");

        Assert.Equal(ErrorCode.Cooldown, result.Error);
        Assert.Equal(Fixture.RootElement.GetProperty("now").GetInt64() + 120, result.NextSendAt);
    }

    [Fact]
    public void TheFixtureIsTheSchemaThisSuiteExpects() =>
        Assert.Equal(2, Fixture.RootElement.GetProperty("schema_version").GetInt32());
}
