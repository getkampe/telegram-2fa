namespace Kampe.TelegramTwoFactor;

/// <summary>
/// The outcome of asking for a code to be issued and delivered.
/// </summary>
/// <remarks>
/// Note what is absent: the code. Neither challenge direction returns it, which
/// is the only reason a result like this can be serialised straight into an HTTP
/// response.
/// </remarks>
public sealed class ChallengeResult
{
    private ChallengeResult(bool ok, string? error, long? expiresAt, long? nextSendAt)
    {
        Ok = ok;
        Error = error;
        ExpiresAt = expiresAt;
        NextSendAt = nextSendAt;
    }

    /// <summary>Whether a code was issued and delivered.</summary>
    public bool Ok { get; }

    /// <summary>An <see cref="ErrorCode"/> value, or null on success.</summary>
    public string? Error { get; }

    /// <summary>When the issued code stops being valid, in Unix seconds.</summary>
    public long? ExpiresAt { get; }

    /// <summary>The earliest a resend may be offered, in Unix seconds.</summary>
    public long? NextSendAt { get; }

    /// <summary>A delivered challenge.</summary>
    public static ChallengeResult Sent(long expiresAt, long nextSendAt) =>
        new(true, null, expiresAt, nextSendAt);

    /// <summary>A refused challenge.</summary>
    public static ChallengeResult Failed(string error, long? nextSendAt = null) =>
        new(false, error, null, nextSendAt);

    /// <summary>Seconds to wait before offering a resend, never negative.</summary>
    public long RetryAfter(long now) => NextSendAt is null ? 0 : Math.Max(0, NextSendAt.Value - now);

    /// <summary>Text safe to show an end user.</summary>
    public string Message => ErrorCode.Message(Error);
}

/// <summary>The outcome of checking a submitted code.</summary>
public sealed class VerificationResult
{
    private VerificationResult(bool ok, string? error, int? attemptsRemaining)
    {
        Ok = ok;
        Error = error;
        AttemptsRemaining = attemptsRemaining;
    }

    /// <summary>Whether the code was accepted.</summary>
    public bool Ok { get; }

    /// <summary>An <see cref="ErrorCode"/> value, or null on success.</summary>
    public string? Error { get; }

    /// <summary>Guesses left against this code, when that is known.</summary>
    public int? AttemptsRemaining { get; }

    /// <summary>An accepted code.</summary>
    public static VerificationResult Passed() => new(true, null, null);

    /// <summary>A rejected code.</summary>
    public static VerificationResult Failed(string error, int? attemptsRemaining = null) =>
        new(false, error, attemptsRemaining);

    /// <summary>Text safe to show an end user.</summary>
    public string Message => ErrorCode.Message(Error);
}

/// <summary>
/// A pending link, ready to be shown to the user.
/// </summary>
/// <remarks>
/// This is the one place a secret legitimately leaves the library, because the
/// user has to receive it somehow. For the deeplink flow put <see cref="Url"/> in
/// a button or a QR code; for the paste flow show <see cref="Token"/> in the chat.
/// Either way it does not belong in a log line or an audit record.
/// </remarks>
/// <param name="Token">The secret the user presents.</param>
/// <param name="ExpiresAt">When it stops resolving, in Unix seconds.</param>
/// <param name="Url">The t.me link, or null when no bot username is configured.</param>
public sealed record LinkRequest(string Token, long ExpiresAt, string? Url);

/// <summary>The outcome of resolving a link token.</summary>
public sealed class LinkResult
{
    private LinkResult(bool ok, Identity? identity, string? error)
    {
        Ok = ok;
        Identity = identity;
        Error = error;
    }

    /// <summary>Whether the chat is now the account's second factor.</summary>
    public bool Ok { get; }

    /// <summary>The enrollment as stored, on success.</summary>
    public Identity? Identity { get; }

    /// <summary>An <see cref="ErrorCode"/> value, or null on success.</summary>
    public string? Error { get; }

    /// <summary>A completed link.</summary>
    public static LinkResult Linked(Identity identity) => new(true, identity, null);

    /// <summary>A refused link.</summary>
    public static LinkResult Failed(string error) => new(false, null, error);

    /// <summary>Text safe to show an end user.</summary>
    public string Message => ErrorCode.Message(Error);
}

/// <summary>
/// The outcome of starting a chat replacement: either an authorised link request,
/// or the verification that stopped it.
/// </summary>
/// <remarks>
/// Modelled as one type rather than a union so a caller cannot read
/// <see cref="Request"/> without having checked <see cref="Ok"/> - the mistake
/// the Node port's "narrow with 'token' in result" invites.
/// </remarks>
public sealed class ReplacementResult
{
    private ReplacementResult(LinkRequest? request, VerificationResult? proof)
    {
        Request = request;
        Proof = proof;
    }

    /// <summary>Whether the replacement was authorised.</summary>
    public bool Ok => Request is not null;

    /// <summary>The link to present, on success.</summary>
    public LinkRequest? Request { get; }

    /// <summary>Why it was refused, on failure.</summary>
    public VerificationResult? Proof { get; }

    /// <summary>An <see cref="ErrorCode"/> value, or null on success.</summary>
    public string? Error => Proof?.Error;

    /// <summary>An authorised replacement.</summary>
    public static ReplacementResult Authorised(LinkRequest request) => new(request, null);

    /// <summary>A refused replacement.</summary>
    public static ReplacementResult Refused(VerificationResult proof) => new(null, proof);
}
