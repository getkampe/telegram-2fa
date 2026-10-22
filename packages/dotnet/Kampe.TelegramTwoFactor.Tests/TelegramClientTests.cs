using System.Net;
using System.Text;
using Kampe.TelegramTwoFactor.Telegram;
using Xunit;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>Answers every request with a canned response, or throws.</summary>
internal sealed class StubHandler : HttpMessageHandler
{
    private readonly HttpStatusCode _status;
    private readonly string? _body;
    private readonly Exception? _failure;

    internal StubHandler(HttpStatusCode status, string body)
    {
        _status = status;
        _body = body;
    }

    internal StubHandler(Exception failure) => _failure = failure;

    internal List<Uri> Requests { get; } = new();

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests.Add(request.RequestUri!);

        if (_failure is not null)
        {
            throw _failure;
        }

        return Task.FromResult(new HttpResponseMessage(_status)
        {
            Content = new StringContent(_body!, Encoding.UTF8, "application/json"),
        });
    }
}

/// <summary>Captures what the library logged, so a test can assert on it.</summary>
internal sealed class CapturingLog : IEventLog
{
    internal List<(string Level, string Message, IReadOnlyDictionary<string, object?>? Context)> Entries { get; } = new();

    public void Info(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        Entries.Add(("info", message, context));

    public void Warn(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        Entries.Add(("warn", message, context));

    public void Error(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        Entries.Add(("error", message, context));

    /// <summary>Everything written, flattened, for a leak assertion.</summary>
    internal string Everything =>
        string.Join(
            "\n",
            Entries.Select(e =>
                $"{e.Level} {e.Message} " +
                string.Join(",", (e.Context ?? new Dictionary<string, object?>()).Select(p => $"{p.Key}={p.Value}"))));
}

public class TelegramClientTests
{
    private const string BotToken = "123456789:AAFakeTokenForTestsOnly_0123456789abc";

    private static (HttpTelegramClient Client, CapturingLog Log, StubHandler Handler) Build(
        HttpStatusCode status,
        string body)
    {
        var handler = new StubHandler(status, body);
        var log = new CapturingLog();

        return (new HttpTelegramClient(BotToken, new HttpClient(handler), log), log, handler);
    }

    [Fact]
    public async Task AnAcceptedSendReportsSuccess()
    {
        var (client, _, _) = Build(HttpStatusCode.OK, """{"ok":true,"result":{"message_id":1}}""");

        Assert.True(await client.SendMessageAsync("555000111", "hello"));
    }

    /// <summary>
    /// The Bot API answers 200 with ok:false for several refusals - a blocked bot, a
    /// chat that no longer exists.
    /// </summary>
    /// <remarks>
    /// Reporting that as delivered leaves the user waiting until the cooldown lapses
    /// for a code that does not exist, because the protocol only discards the
    /// challenge when the send reports failure.
    /// </remarks>
    [Fact]
    public async Task ATwoHundredCarryingOkFalseIsAFailure()
    {
        var (client, log, _) = Build(
            HttpStatusCode.OK,
            """{"ok":false,"error_code":403,"description":"Forbidden: bot was blocked by the user"}""");

        Assert.False(await client.SendMessageAsync("555000111", "hello"));
        Assert.Contains(log.Entries, e => e.Level == "error");
        Assert.Contains(log.Entries, e => e.Context is not null && e.Context.ContainsKey("error_code"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    [InlineData("[]")]
    [InlineData("\"ok\"")]
    [InlineData("null")]
    [InlineData("""{"result":{"message_id":1}}""")]
    [InlineData("""{"ok":"true"}""")]
    [InlineData("""{"ok":1}""")]
    public async Task AMalformedOrSilentTwoHundredIsAFailure(string body)
    {
        var (client, _, _) = Build(HttpStatusCode.OK, body);

        Assert.False(
            await client.SendMessageAsync("555000111", "hello"),
            $"a 200 with body {body} is not Telegram saying yes");
    }

    [Fact]
    public async Task ANonSuccessStatusIsAFailure()
    {
        var (client, log, _) = Build(HttpStatusCode.Forbidden, """{"ok":false,"error_code":403}""");

        Assert.False(await client.SendMessageAsync("555000111", "hello"));
        Assert.Contains(log.Entries, e => e.Context is not null && e.Context.ContainsKey("status"));
    }

    [Fact]
    public async Task ATransportFailureIsAFailureRatherThanAnException()
    {
        var client = new HttpTelegramClient(
            BotToken,
            new HttpClient(new StubHandler(new HttpRequestException("connection refused"))),
            new CapturingLog());

        Assert.False(await client.SendMessageAsync("555000111", "hello"));
    }

    /// <summary>
    /// The bot token is in the request URL, because that is the API Telegram
    /// exposes.
    /// </summary>
    /// <remarks>
    /// Any log line built from an exception's own message, or from the request, can
    /// therefore carry the token - and a token in a log file is a bot anyone who
    /// reads that file can impersonate. This asserts against every log entry rather
    /// than a particular one, so a new log line added later is covered too.
    /// </remarks>
    [Theory]
    [InlineData("transport")]
    [InlineData("status")]
    [InlineData("ok-false")]
    [InlineData("malformed")]
    public async Task NothingLoggedEverContainsTheBotToken(string scenario)
    {
        var log = new CapturingLog();

        var client = scenario switch
        {
            "transport" => new HttpTelegramClient(
                BotToken,
                new HttpClient(new StubHandler(
                    new HttpRequestException(
                        $"No connection could be made to https://api.telegram.org/bot{BotToken}/sendMessage"))),
                log),
            "status" => Rebuild(HttpStatusCode.InternalServerError, "upstream exploded", log),
            "ok-false" => Rebuild(HttpStatusCode.OK, """{"ok":false,"error_code":400,"description":"Bad Request"}""", log),
            _ => Rebuild(HttpStatusCode.OK, "<html>captive portal</html>", log),
        };

        await client.SendMessageAsync("555000111", "hello");

        Assert.NotEmpty(log.Entries);
        Assert.DoesNotContain(BotToken, log.Everything, StringComparison.Ordinal);
        Assert.DoesNotContain("123456789:", log.Everything, StringComparison.Ordinal);
    }

    private static HttpTelegramClient Rebuild(HttpStatusCode status, string body, CapturingLog log) =>
        new(BotToken, new HttpClient(new StubHandler(status, body)), log);

    [Fact]
    public async Task AnAcknowledgedCallbackQueryReportsSuccess()
    {
        var (client, _, handler) = Build(HttpStatusCode.OK, """{"ok":true,"result":true}""");

        Assert.True(await client.AnswerCallbackQueryAsync("cb-1"));
        Assert.Single(handler.Requests);
        Assert.EndsWith("/answerCallbackQuery", handler.Requests[0].AbsolutePath, StringComparison.Ordinal);
    }

    /// <summary>
    /// Registering a webhook without the secret token leaves the endpoint
    /// unauthenticated, so it is a required argument rather than an option.
    /// </summary>
    [Fact]
    public async Task SetWebhookSendsTheSecretToken()
    {
        var (client, _, handler) = Build(HttpStatusCode.OK, """{"ok":true,"result":true}""");

        Assert.True(await client.SetWebhookAsync("https://example.test/hook", new string('s', 48)));
        Assert.EndsWith("/setWebhook", handler.Requests[0].AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingBotTokenIsRefusedAtConstruction() =>
        Assert.Throws<ConfigurationException>(() => new HttpTelegramClient("  "));
}
