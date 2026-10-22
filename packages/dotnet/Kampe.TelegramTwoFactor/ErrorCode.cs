namespace Kampe.TelegramTwoFactor;

/// <summary>
/// The error vocabulary of SPEC.md section 10.
/// </summary>
/// <remarks>
/// These strings are the wire form of the protocol, shared with every other
/// implementation, so a client written against them works against any of them.
/// Do not change the values.
/// </remarks>
public static class ErrorCode
{
    /// <summary>The account has no verified Telegram link.</summary>
    public const string NotLinked = "not_linked";

    /// <summary>The account, or the chat, is already linked.</summary>
    public const string AlreadyLinked = "already_linked";

    /// <summary>A code was sent too recently; the result carries the next send time.</summary>
    public const string Cooldown = "cooldown";

    /// <summary>Telegram did not accept the message.</summary>
    public const string SendFailed = "send_failed";

    /// <summary>The submitted code does not match.</summary>
    public const string Invalid = "invalid";

    /// <summary>No live code: never issued, aged out, or already used.</summary>
    public const string Expired = "expired";

    /// <summary>The attempt budget for this code is exhausted.</summary>
    public const string TooManyAttempts = "too_many_attempts";

    /// <summary>Link token unknown, expired or already used.</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>Webhook secret token missing or wrong.</summary>
    public const string WebhookUnauthorized = "webhook_unauthorized";

    /// <summary>
    /// Messages safe to show an end user.
    /// </summary>
    /// <remarks>
    /// Deliberately vague about which of "never issued", "expired" and "already
    /// used" applies, because distinguishing them tells an attacker holding a
    /// session whether a challenge is in flight.
    /// </remarks>
    public static readonly IReadOnlyDictionary<string, string> Messages =
        new Dictionary<string, string>
        {
            [NotLinked] = "No Telegram account is linked to this profile.",
            [AlreadyLinked] = "This Telegram account is already linked.",
            [Cooldown] = "A code was just sent. Please wait before requesting another.",
            [SendFailed] = "The code could not be delivered. Please try again or use another method.",
            [Invalid] = "That code is not valid.",
            [Expired] = "That code is no longer valid. Request a new one.",
            [TooManyAttempts] = "Too many incorrect attempts. Request a new code.",
            [InvalidToken] = "This link has expired or has already been used.",
            [WebhookUnauthorized] = "Unauthorized.",
        };

    /// <summary>Text safe to show an end user for the given code.</summary>
    public static string Message(string? code) =>
        code is not null && Messages.TryGetValue(code, out var message)
            ? message
            : "Verification failed.";
}

/// <summary>
/// Purposes name the step a code authorises.
/// </summary>
public static class Purpose
{
    /// <summary>The default, for an ordinary sign-in.</summary>
    public const string Login = "login";

    /// <summary>
    /// The purpose of a code the user fetched themselves with /code.
    /// </summary>
    /// <remarks>
    /// Such a code carries no knowledge of what it is about to authorise, so it
    /// satisfies any requested purpose. That is sound because the user asked for
    /// it deliberately - nothing the application did caused it to exist.
    /// </remarks>
    public const string OnDemand = "on_demand";

    /// <summary>Proving the current factor before rebinding to a new chat.</summary>
    public const string Replace = "replace";

    /// <summary>Proving the current factor before removing it.</summary>
    public const string Unlink = "unlink";
}
