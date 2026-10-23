namespace Kampe.TelegramTwoFactor;

/// <summary>
/// An account's Telegram enrollment, as the identity store holds it.
/// </summary>
/// <remarks>
/// This represents the row rather than only the linked state, so an account that
/// has been unlinked still has an <see cref="Identity"/> - carrying no chat, but
/// carrying the generation. That is deliberate: revocation has to outlive the
/// binding it revokes, or a token minted before an unlink would come back to life
/// when the user links again.
/// </remarks>
/// <param name="UserId">The account, opaque to this library.</param>
/// <param name="ChatId">The Telegram chat, or null when unlinked.</param>
/// <param name="LinkedAt">Unix seconds the link was verified, or null.</param>
/// <param name="Generation">The enrollment generation; see <see cref="Generations"/>.</param>
public sealed record Identity(
    string UserId,
    string? ChatId,
    long? LinkedAt,
    string? Generation)
{
    /// <summary>
    /// Only a verified link counts as a second factor.
    /// </summary>
    /// <remarks>
    /// A row carrying a chat id with no verification timestamp is a link that was
    /// started and never completed. Treating it as linked would let anyone who can
    /// write a chat id into the row satisfy a challenge.
    /// </remarks>
    public bool IsVerified => !string.IsNullOrEmpty(ChatId) && LinkedAt is not null;
}

/// <summary>Enrollment generation sentinels.</summary>
public static class Generations
{
    /// <summary>
    /// Expectation meaning "whatever is there now".
    /// </summary>
    /// <remarks>
    /// For recovery paths where the caller has already proved identity by other
    /// means and must not be blocked by a concurrent change. The NUL byte keeps it
    /// outside the space of real generations, which are hex.
    /// </remarks>
    public const string Any = "\0any";
}

/// <summary>Convenience for the many places that must tolerate a null identity.</summary>
public static class IdentityExtensions
{
    /// <summary>
    /// Whether this is a verified second factor.
    /// </summary>
    /// <remarks>
    /// The attribute is what lets the compiler carry the null check across the call,
    /// so every site that has established a verified factor can read the identity
    /// without a null-forgiving operator. Those operators are exactly what hides a
    /// real null from review.
    /// </remarks>
    public static bool IsVerifiedFactor(
        [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] this Identity? identity) =>
        identity is not null && identity.IsVerified;
}
