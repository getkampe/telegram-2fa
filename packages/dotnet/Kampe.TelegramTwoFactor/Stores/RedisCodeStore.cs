namespace Kampe.TelegramTwoFactor.Stores;

/// <summary>
/// The Redis commands this store needs, as a contract your client adapter
/// implements.
/// </summary>
/// <remarks>
/// Nominal rather than structural, so an adapter that does not supply an atomic
/// get-and-delete does not type-check. That is a weaker guarantee than it looks:
/// the compiler can require <see cref="GetDeleteAsync"/> to <em>exist</em>, and it
/// cannot check that what you wrote inside it is atomic. An implementation that
/// issues a GET and then a DEL compiles perfectly and races exactly as the other
/// ports' unsafe clients do.
/// <para>
/// So this is a prompt, not a proof: the signature makes the requirement
/// impossible to overlook, and the rest is on whoever writes the adapter.
/// Three-line summary of the obligation - one server round trip, GETDEL on Redis
/// 6.2+, EVAL of a GET-then-DEL script on anything older, never two calls from
/// here.
/// </para>
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
