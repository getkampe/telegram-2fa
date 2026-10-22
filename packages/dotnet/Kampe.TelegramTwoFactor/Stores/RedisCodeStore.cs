namespace Kampe.TelegramTwoFactor.Stores;

/// <summary>
/// The Redis commands this store needs, as a contract your client adapter
/// implements.
/// </summary>
/// <remarks>
/// Nominal rather than structural, which turns a runtime hazard into a compile
/// error. The other implementations of this protocol have to probe their client at
/// construction and throw when it offers no atomic get-and-delete, because a
/// duck-typed client might not have one. Here an adapter that cannot do it will
/// not compile, so the unsafe shape is unreachable rather than merely rejected.
/// <para>
/// The library depends on no Redis package. A StackExchange.Redis adapter is about
/// twenty lines - see README.md.
/// </para>
/// </remarks>
public interface IRedisCommands
{
    /// <summary>GET.</summary>
    Task<string?> GetAsync(string key, CancellationToken cancellationToken);

    /// <summary>DEL.</summary>
    Task DeleteAsync(string key, CancellationToken cancellationToken);

    /// <summary>
    /// SET key value EX ttl, with NX when <paramref name="onlyIfAbsent"/>.
    /// </summary>
    /// <returns>
    /// Whether the value was stored. False only ever means NX declined - and it
    /// must mean that: a client that reports a refusal as success turns the cooldown
    /// into no cooldown at all and makes the webhook process an update twice.
    /// </returns>
    Task<bool> SetAsync(
        string key,
        string value,
        int ttlSeconds,
        bool onlyIfAbsent,
        CancellationToken cancellationToken);

    /// <summary>
    /// GETDEL, or EVAL of a GET-then-DEL script on servers older than Redis 6.2.
    /// </summary>
    /// <remarks>
    /// One round trip, server-side. A GET followed by a DEL from the client would
    /// let two simultaneous verifications of the same code both succeed, which is
    /// the single-use guarantee gone.
    /// </remarks>
    Task<string?> GetDeleteAsync(string key, CancellationToken cancellationToken);
}

/// <summary>
/// A production code store on Redis.
/// </summary>
/// <remarks>
/// Values are the JSON of SPEC.md section 9, in the key layout of the same
/// section, so the other implementations read and write the same records against
/// the same server.
/// <para>
/// TTLs are Redis's own, which is why each record also carries its own
/// <c>expires_at</c>: the two must agree, and the explicit field is what keeps
/// expiry correct against a replica whose clock has drifted or a store with coarse
/// TTL granularity.
/// </para>
/// </remarks>
public sealed class RedisCodeStore : ICodeStore
{
    private readonly IRedisCommands _redis;

    /// <summary>Creates the store.</summary>
    public RedisCodeStore(IRedisCommands redis) =>
        _redis = redis ?? throw new ArgumentNullException(nameof(redis));

    /// <inheritdoc />
    public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default) =>
        _redis.GetAsync(key, cancellationToken);

    /// <inheritdoc />
    public Task PutAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default) =>
        _redis.SetAsync(key, value, ttlSeconds, false, cancellationToken);

    /// <inheritdoc />
    public Task ForgetAsync(string key, CancellationToken cancellationToken = default) =>
        _redis.DeleteAsync(key, cancellationToken);

    /// <inheritdoc />
    public Task<string?> TakeAsync(string key, CancellationToken cancellationToken = default) =>
        _redis.GetDeleteAsync(key, cancellationToken);

    /// <inheritdoc />
    public Task<bool> AddAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default) =>
        _redis.SetAsync(key, value, ttlSeconds, true, cancellationToken);
}
