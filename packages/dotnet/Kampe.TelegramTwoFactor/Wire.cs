using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kampe.TelegramTwoFactor;

/// <summary>
/// A live challenge, as SPEC.md section 9 defines it on the wire.
/// </summary>
/// <remarks>
/// The property names are the protocol. Every implementation reads and writes
/// these exact keys, which is what lets them share one store, and the fixtures in
/// /conformance are read by all of their test suites to check that rather than
/// assert it.
/// </remarks>
internal sealed class ChallengeRecord
{
    [JsonPropertyName("hash")]
    public string? Hash { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("attempts")]
    public int Attempts { get; set; }

    [JsonPropertyName("purpose")]
    public string? Purpose { get; set; }

    // Written even when null: a row migrated from a version before the generation
    // existed has none, and verify accepts such a challenge only while the account
    // still has none, so the difference between "absent" and "null" matters.
    [JsonPropertyName("generation")]
    public string? Generation { get; set; }

    [JsonPropertyName("challenge_id")]
    public string? ChallengeId { get; set; }
}

/// <summary>A pending link token, for either linking flow.</summary>
internal sealed class LinkRecord
{
    [JsonPropertyName("user_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserId { get; set; }

    [JsonPropertyName("chat_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ChatId { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    // Omitted on an ordinary token, so its record is exactly the two fields the
    // conformance fixture holds. The mark lives here, on the stored token, and not
    // on the call that resolves it: taking it from the resolution side would make
    // the proof skippable by presenting an ordinary token.
    [JsonPropertyName("replace")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Replace { get; set; }

    [JsonPropertyName("generation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Generation { get; set; }
}

/// <summary>Reads and writes the store's wire format.</summary>
internal static class Wire
{
    private static readonly JsonSerializerOptions Options = new()
    {
        // Another implementation may hand back a number as a string - Laravel's
        // Redis cache leaves bare numerics unserialised so INCR still works on
        // them, and some drivers stringify every scalar. Tolerating that costs
        // nothing and a refusal here would be a failed verification.
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    internal static string Write<T>(T value) => JsonSerializer.Serialize(value, Options);

    /// <summary>
    /// Reads a record, treating anything unreadable as absent.
    /// </summary>
    /// <remarks>
    /// A key holding something this library did not write - a collision with
    /// another application's prefix - must not throw from inside a verification
    /// path. Absent is the safe reading.
    /// </remarks>
    internal static T? Read<T>(string? raw)
        where T : class
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<T>(raw, Options);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static string WriteTimestamp(long value) =>
        value.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Reads a bare timestamp, as the cooldown record is stored.
    /// </summary>
    /// <remarks>
    /// Not an object: SPEC.md section 9 specifies a plain integer here, because
    /// that is what lets a store use INCR-style primitives on it. Quotes are
    /// tolerated for the same reason the options above allow them.
    /// </remarks>
    internal static long? ReadTimestamp(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        var trimmed = raw.Trim().Trim('"');

        return long.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }
}
