namespace Kampe.TelegramTwoFactor;

/// <summary>
/// Wall clock, injectable so expiry and cooldown are testable without sleeping.
/// </summary>
public interface IClock
{
    /// <summary>The current time, in Unix seconds.</summary>
    long Now { get; }
}

/// <summary>The system clock.</summary>
public sealed class SystemClock : IClock
{
    /// <inheritdoc />
    public long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}

/// <summary>
/// A clock that moves only when you move it.
/// </summary>
/// <remarks>
/// Shipped in the library rather than the test project so applications can test
/// their own expiry handling without sleeping through it.
/// </remarks>
public sealed class FrozenClock : IClock
{
    private long _now;

    /// <summary>Creates a clock stopped at the given time.</summary>
    public FrozenClock(long now = 1_700_000_000) => _now = now;

    /// <inheritdoc />
    public long Now => Interlocked.Read(ref _now);

    /// <summary>Moves the clock forward.</summary>
    public FrozenClock Advance(long seconds)
    {
        Interlocked.Add(ref _now, seconds);

        return this;
    }

    /// <summary>Moves the clock to an absolute time.</summary>
    public FrozenClock SetTo(long timestamp)
    {
        Interlocked.Exchange(ref _now, timestamp);

        return this;
    }
}

/// <summary>
/// Where this library reports what it did.
/// </summary>
/// <remarks>
/// Named so it cannot be confused with Microsoft.Extensions.Logging.ILogger,
/// which the library deliberately does not depend on.
/// <para>
/// Nothing passed here contains a code, a link token or a raw update body - and
/// the update body is the important one, because for this bot the update body
/// <em>is</em> the code.
/// </para>
/// </remarks>
public interface IEventLog
{
    /// <summary>Something routine happened.</summary>
    void Info(string message, IReadOnlyDictionary<string, object?>? context = null);

    /// <summary>Something suspicious or unexpected happened.</summary>
    void Warn(string message, IReadOnlyDictionary<string, object?>? context = null);

    /// <summary>Something failed.</summary>
    void Error(string message, IReadOnlyDictionary<string, object?>? context = null);
}

/// <summary>
/// Discards everything. The default, so the library never writes to a log the
/// host application did not hand it.
/// </summary>
public sealed class NullEventLog : IEventLog
{
    /// <summary>The shared instance.</summary>
    public static readonly NullEventLog Instance = new();

    /// <inheritdoc />
    public void Info(string message, IReadOnlyDictionary<string, object?>? context = null)
    {
    }

    /// <inheritdoc />
    public void Warn(string message, IReadOnlyDictionary<string, object?>? context = null)
    {
    }

    /// <inheritdoc />
    public void Error(string message, IReadOnlyDictionary<string, object?>? context = null)
    {
    }
}

/// <summary>
/// Adapts any logging framework through one callback.
/// </summary>
/// <remarks>
/// Keeps the library dependency-free: wire it to Microsoft.Extensions.Logging,
/// Serilog or anything else in three lines at the call site.
/// </remarks>
public sealed class DelegateEventLog : IEventLog
{
    private readonly Action<string, string, IReadOnlyDictionary<string, object?>?> _write;

    /// <summary>
    /// Creates the adapter.
    /// </summary>
    /// <param name="write">Receives the level ("info", "warn", "error"), the message and the context.</param>
    public DelegateEventLog(Action<string, string, IReadOnlyDictionary<string, object?>?> write) =>
        _write = write ?? throw new ArgumentNullException(nameof(write));

    /// <inheritdoc />
    public void Info(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        _write("info", message, context);

    /// <inheritdoc />
    public void Warn(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        _write("warn", message, context);

    /// <inheritdoc />
    public void Error(string message, IReadOnlyDictionary<string, object?>? context = null) =>
        _write("error", message, context);
}

/// <summary>
/// Short-lived protocol state: challenges, link tokens, cooldowns and webhook
/// claims.
/// </summary>
/// <remarks>
/// Values are the JSON text of SPEC.md section 9, so the store is a plain
/// string-to-string map with expiry and the wire format stays owned by this
/// library rather than by each adapter.
/// <para>
/// <strong>Why five methods.</strong> <see cref="TakeAsync"/> and
/// <see cref="AddAsync"/> are not a convenience. Single use and the attempt
/// budget are read-modify-write sequences, so built from get-check-delete they
/// race: two verifications arriving together both read the live record, both
/// match, and both succeed, while the attempt counter loses increments to the
/// same lost update.
/// </para>
/// </remarks>
public interface ICodeStore
{
    /// <summary>Reads a value, or null when absent or expired.</summary>
    Task<string?> GetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Writes a value with a lifetime, replacing whatever was there.</summary>
    Task PutAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default);

    /// <summary>Removes a value.</summary>
    Task ForgetAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically reads a value and removes it.
    /// </summary>
    /// <remarks>
    /// Exactly one caller may receive a given value. This is what makes a code
    /// single-use: the winner holds the only copy and either accepts it or writes
    /// it back with one more attempt spent. Redis GETDEL, or EVAL on servers
    /// older than 6.2 - never a GET followed by a DEL.
    /// </remarks>
    Task<string?> TakeAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically writes only if the key is absent, reporting whether it did.
    /// </summary>
    /// <remarks>
    /// The boolean is the point: it makes the write a reservation exactly one
    /// caller can win, which is how the cooldown and the webhook's idempotency
    /// claim avoid check-then-write races. Redis SET NX.
    /// </remarks>
    Task<bool> AddAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default);
}

/// <summary>
/// The enrollment table, over your own users.
/// </summary>
/// <remarks>
/// One mutating method on purpose: a link/unlink pair invites read-then-write,
/// and the window between validating a replacement token and writing the binding
/// is where that token outlives the enrollment it proved. Hand the store the
/// generation you expect and let it decide.
/// </remarks>
public interface IIdentityStore
{
    /// <summary>
    /// The row for an account, or null if there has never been one.
    /// </summary>
    /// <remarks>
    /// Returned even when no chat is linked: the generation outlives the binding,
    /// so a token minted before an unlink stays void after a relink.
    /// </remarks>
    Task<Identity?> FindByUserIdAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>The row holding a chat, or null.</summary>
    Task<Identity?> FindByChatIdAsync(string chatId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compare-and-set the enrollment.
    /// </summary>
    /// <param name="userId">The account.</param>
    /// <param name="chatId">The chat to bind, or null to unlink.</param>
    /// <param name="expected">
    /// The generation the caller believes is current; null means "none recorded
    /// yet"; <see cref="Generations.Any"/> skips the check.
    /// </param>
    /// <param name="nextGeneration">The generation to record.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>
    /// The stored row, or null when the expectation did not hold - in which case
    /// nothing was written.
    /// </returns>
    /// <remarks>
    /// The comparison must be part of the write. Validating in application code
    /// and then writing leaves a window in which a recovery can land and be
    /// silently overwritten.
    /// </remarks>
    /// <exception cref="ChatAlreadyLinkedException">
    /// The chat already belongs to a different account. Enforce this with a unique
    /// index, not only an application check.
    /// </exception>
    Task<Identity?> TransitionAsync(
        string userId,
        string? chatId,
        string? expected,
        string nextGeneration,
        CancellationToken cancellationToken = default);
}

/// <summary>The slice of the Telegram Bot API this library uses.</summary>
public interface ITelegramClient
{
    /// <summary>
    /// Sends a message, reporting whether Telegram accepted it.
    /// </summary>
    /// <remarks>
    /// False rather than an exception, because a delivery failure is an ordinary
    /// outcome the protocol handles: the challenge is discarded so the user is not
    /// left waiting for a code that will never arrive.
    /// </remarks>
    Task<bool> SendMessageAsync(
        string chatId,
        string text,
        IReadOnlyList<IReadOnlyList<(string Text, string Data)>>? inlineKeyboard = null,
        CancellationToken cancellationToken = default);

    /// <summary>Acknowledges a callback query, so the user's client stops spinning.</summary>
    Task<bool> AnswerCallbackQueryAsync(
        string callbackQueryId,
        string? text = null,
        CancellationToken cancellationToken = default);
}

/// <summary>The bot's outgoing copy. Implement to translate or restyle.</summary>
public interface IMessages
{
    /// <summary>A verification code.</summary>
    string Code(string code, int ttlSeconds);

    /// <summary>How to finish the paste flow.</summary>
    string LinkInstructions(string code, int ttlSeconds, string appName);

    /// <summary>The link is now live.</summary>
    string LinkSucceeded(string accountLabel, string appName);

    /// <summary>The link token did not resolve.</summary>
    string LinkTokenInvalid();

    /// <summary>This chat is already a factor.</summary>
    string AlreadyLinked();

    /// <summary>This chat is not a factor.</summary>
    string NotLinked(string appName);

    /// <summary>A code was sent too recently.</summary>
    string Cooldown(long secondsRemaining);

    /// <summary>Where to remove the factor, and why not here.</summary>
    string UnlinkInstructions(string appName);

    /// <summary>The factor has been removed.</summary>
    string Unlinked(string appName);

    /// <summary>The bot's front page.</summary>
    string Welcome(bool isLinked, string appName);

    /// <summary>Anything the bot does not understand.</summary>
    string UnknownCommand();
}
