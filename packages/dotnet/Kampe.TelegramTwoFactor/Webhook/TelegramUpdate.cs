using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kampe.TelegramTwoFactor.Webhook;

/// <summary>One webhook update, in the subset of Telegram's schema this library reads.</summary>
public sealed class TelegramUpdate
{
    /// <summary>Telegram's id for this update, used for deduplication.</summary>
    [JsonPropertyName("update_id")]
    public long? UpdateId { get; set; }

    /// <summary>A message, when the update is one.</summary>
    [JsonPropertyName("message")]
    public TelegramMessage? Message { get; set; }

    /// <summary>A button press, when the update is one.</summary>
    [JsonPropertyName("callback_query")]
    public TelegramCallbackQuery? CallbackQuery { get; set; }

    /// <summary>
    /// Parses an update body, returning null when it is not JSON at all.
    /// </summary>
    /// <remarks>
    /// Null rather than an exception: a malformed body on a public endpoint is
    /// something to answer 200 to and ignore, not something to turn into a 500 that
    /// makes Telegram retry it forever.
    /// </remarks>
    public static TelegramUpdate? Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<TelegramUpdate>(json, UpdateJson.Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>A chat message.</summary>
public sealed class TelegramMessage
{
    /// <summary>Telegram's id for the message.</summary>
    [JsonPropertyName("message_id")]
    public long? MessageId { get; set; }

    /// <summary>The message text, when it has any.</summary>
    [JsonPropertyName("text")]
    public string? Text { get; set; }

    /// <summary>The chat it arrived in.</summary>
    [JsonPropertyName("chat")]
    public TelegramChat? Chat { get; set; }
}

/// <summary>A chat.</summary>
public sealed class TelegramChat
{
    /// <summary>
    /// The chat id.
    /// </summary>
    /// <remarks>
    /// Telegram sends this as a JSON number, and a hand-written test or another
    /// implementation may write it as a string. Both are read, because an update
    /// silently dropped for the shape of one field is a bug that looks like a
    /// network problem.
    /// </remarks>
    [JsonPropertyName("id")]
    public long? Id { get; set; }

    /// <summary>"private", "group", "supergroup" or "channel".</summary>
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    /// <summary>The chat id as this library uses it: an opaque string.</summary>
    [JsonIgnore]
    public string? ChatId => Id?.ToString(CultureInfo.InvariantCulture);
}

/// <summary>An inline-keyboard button press.</summary>
public sealed class TelegramCallbackQuery
{
    /// <summary>The query id, which must be acknowledged.</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>The callback_data of the button.</summary>
    [JsonPropertyName("data")]
    public string? Data { get; set; }

    /// <summary>The message the keyboard was attached to.</summary>
    [JsonPropertyName("message")]
    public TelegramMessage? Message { get; set; }
}

internal static class UpdateJson
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        PropertyNameCaseInsensitive = false,
    };
}
