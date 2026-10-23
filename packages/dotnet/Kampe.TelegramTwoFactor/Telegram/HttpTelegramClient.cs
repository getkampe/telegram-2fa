using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kampe.TelegramTwoFactor.Telegram;

/// <summary>
/// The Telegram Bot API over <see cref="HttpClient"/>.
/// </summary>
/// <remarks>
/// Pass your own <see cref="HttpClient"/> so it comes from IHttpClientFactory and
/// inherits your application's handler, retry policy and socket lifetime. The
/// token is appended to the request URL because that is the API Telegram exposes,
/// which is also why nothing here is logged: the URL contains the bot token and
/// the body contains the codes.
/// </remarks>
public sealed class HttpTelegramClient : ITelegramClient, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _botToken;
    private readonly IEventLog _log;

    /// <summary>Creates the client.</summary>
    /// <param name="botToken">The token from @BotFather.</param>
    /// <param name="httpClient">Your client; one is created and owned if null.</param>
    /// <param name="log">Where failures are reported.</param>
    public HttpTelegramClient(string botToken, HttpClient? httpClient = null, IEventLog? log = null)
    {
        if (string.IsNullOrWhiteSpace(botToken))
        {
            throw new ConfigurationException("A bot token is required.");
        }

        _botToken = botToken;
        _ownsHttp = httpClient is null;
        _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _log = log ?? NullEventLog.Instance;
    }

    /// <inheritdoc />
    public async Task<bool> SendMessageAsync(
        string chatId,
        string text,
        IReadOnlyList<IReadOnlyList<(string Text, string Data)>>? inlineKeyboard = null,
        CancellationToken cancellationToken = default)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["chat_id"] = chatId,
            ["text"] = text,
            ["parse_mode"] = "HTML",
            ["disable_web_page_preview"] = true,
        };

        if (inlineKeyboard is { Count: > 0 })
        {
            payload["reply_markup"] = new
            {
                inline_keyboard = inlineKeyboard
                    .Select(row => row
                        .Select(button => new { text = button.Text, callback_data = button.Data })
                        .ToArray())
                    .ToArray(),
            };
        }

        return await PostAsync("sendMessage", payload, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<bool> AnswerCallbackQueryAsync(
        string callbackQueryId,
        string? text = null,
        CancellationToken cancellationToken = default)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["callback_query_id"] = callbackQueryId,
        };

        if (text is not null)
        {
            payload["text"] = text;
        }

        return PostAsync("answerCallbackQuery", payload, cancellationToken);
    }

    /// <summary>Registers the webhook, with the secret token Telegram will echo.</summary>
    /// <remarks>
    /// Registering without <paramref name="secretToken"/> leaves the endpoint
    /// unauthenticated, so this takes it as a required argument rather than an
    /// option.
    /// </remarks>
    public Task<bool> SetWebhookAsync(
        string url,
        string secretToken,
        IReadOnlyList<string>? allowedUpdates = null,
        CancellationToken cancellationToken = default)
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["url"] = url,
            ["secret_token"] = secretToken,
            ["allowed_updates"] = allowedUpdates ?? new[] { "message", "callback_query" },
            ["drop_pending_updates"] = false,
        };

        return PostAsync("setWebhook", payload, cancellationToken);
    }

    /// <summary>Removes the webhook.</summary>
    public Task<bool> DeleteWebhookAsync(CancellationToken cancellationToken = default) =>
        PostAsync("deleteWebhook", new Dictionary<string, object?>(StringComparer.Ordinal), cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private async Task<bool> PostAsync(
        string method,
        Dictionary<string, object?> payload,
        CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _http
                .PostAsJsonAsync($"https://api.telegram.org/bot{_botToken}/{method}", payload, JsonOptions, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // The method and the status, never the payload or the URL: one holds
                // the codes and the other holds the bot token.
                _log.Error(
                    "telegram-2fa: Telegram rejected a request",
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["method"] = method,
                        ["status"] = (int)response.StatusCode,
                    });

                return false;
            }

            // A 2xx is not an acceptance. The Bot API answers 200 with
            // {"ok":false,...} for several refusals - a blocked bot, a chat that no
            // longer exists - and a proxy or captive portal can answer 200 with
            // something else entirely. Treating the status alone as success reports a
            // code as delivered that the user never received, which is worse than a
            // visible failure: the protocol discards the challenge on a false return,
            // so the user can ask again, but on a false success they are left waiting
            // for a code that does not exist until the cooldown lapses.
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!Accepted(body, out var errorCode))
            {
                _log.Error(
                    "telegram-2fa: Telegram did not accept a request it answered 200 to",
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["method"] = method,
                        // The error code, not the description: a description is
                        // Telegram's text and the payload is ours, and the payload is
                        // the code. Nothing here is worth the risk of the two ever
                        // being conflated.
                        ["error_code"] = errorCode,
                    });

                return false;
            }

            return true;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            // A delivery failure is an ordinary outcome the protocol handles: the
            // caller discards the challenge so the user is not left waiting for a
            // code that will never arrive.
            _log.Error(
                "telegram-2fa: Telegram request failed",
                new Dictionary<string, object?>(StringComparer.Ordinal)
                {
                    ["method"] = method,
                    ["error"] = exception.GetType().Name,
                });

            return false;
        }
    }

    /// <summary>
    /// Whether a 200 response body is an acceptance.
    /// </summary>
    /// <remarks>
    /// Requires the <c>ok</c> field to be present and true. An empty body, a body
    /// that is not JSON, a JSON value that is not an object, and an object with no
    /// <c>ok</c> field are all refusals: none of them is Telegram saying yes, and
    /// guessing in the caller's favour is how a code gets reported as delivered when
    /// it was not.
    /// </remarks>
    private static bool Accepted(string body, out int? errorCode)
    {
        errorCode = null;

        if (string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(body);

            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (document.RootElement.TryGetProperty("error_code", out var code)
                && code.ValueKind == JsonValueKind.Number)
            {
                errorCode = code.GetInt32();
            }

            return document.RootElement.TryGetProperty("ok", out var ok)
                && ok.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
