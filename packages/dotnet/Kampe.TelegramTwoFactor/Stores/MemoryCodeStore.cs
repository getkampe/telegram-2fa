namespace Kampe.TelegramTwoFactor.Stores;

/// <summary>
/// An in-process code store, for tests and single-process applications.
/// </summary>
/// <remarks>
/// Not for production behind more than one process or machine: each would hold
/// its own copy, so a code issued by one request would be invisible to the next.
/// Use Redis, or a table with an expires_at column.
/// <para>
/// <strong>Why every mutation holds the lock.</strong> A read-modify-write
/// sequence is not atomic just because each step is: the scheduler can preempt
/// between any two operations, so two threads can both read a record before either
/// deletes it - and then a single-use code is used twice and the attempt counter
/// loses increments. A concurrent dictionary would not fix
/// that either, because the window is between its calls and not inside them. The
/// lock is what actually serialises them, and the tests spawn real threads to
/// prove it.
/// </para>
/// <para>
/// Each method completes synchronously inside the lock and returns a finished
/// task. There is no await in a critical section here, and the compiler would
/// refuse one.
/// </para>
/// </remarks>
public sealed class MemoryCodeStore : ICodeStore
{
    private readonly Dictionary<string, (string Value, long ExpiresAt)> _items = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly IClock _clock;

    /// <summary>Creates the store.</summary>
    public MemoryCodeStore(IClock? clock = null) => _clock = clock ?? new SystemClock();

    /// <inheritdoc />
    public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(Read(key));
        }
    }

    /// <inheritdoc />
    public Task PutAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _items[key] = (value, _clock.Now + ttlSeconds);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ForgetAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _items.Remove(key);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<string?> TakeAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            var value = Read(key);
            _items.Remove(key);

            return Task.FromResult(value);
        }
    }

    /// <inheritdoc />
    public Task<bool> AddAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (Read(key) is not null)
            {
                return Task.FromResult(false);
            }

            _items[key] = (value, _clock.Now + ttlSeconds);

            return Task.FromResult(true);
        }
    }

    /// <summary>Caller must hold the lock.</summary>
    private string? Read(string key)
    {
        if (!_items.TryGetValue(key, out var item))
        {
            return null;
        }

        if (item.ExpiresAt <= _clock.Now)
        {
            _items.Remove(key);

            return null;
        }

        return item.Value;
    }
}

/// <summary>
/// An in-memory identity store, for tests and for sketching an integration before
/// wiring it to a database.
/// </summary>
/// <remarks>
/// It models both rules a real store must enforce: one chat belongs to one
/// account, and a transition only applies when the stored generation is the one the
/// caller expected. Rows survive unlinking, because the generation has to.
/// </remarks>
public sealed class MemoryIdentityStore : IIdentityStore
{
    private readonly Dictionary<string, Identity> _rows = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly IClock _clock;

    /// <summary>Creates the store.</summary>
    public MemoryIdentityStore(IClock? clock = null) => _clock = clock ?? new SystemClock();

    /// <inheritdoc />
    public Task<Identity?> FindByUserIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_rows.TryGetValue(userId, out var row) ? row : null);
        }
    }

    /// <inheritdoc />
    public Task<Identity?> FindByChatIdAsync(string chatId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(ByChatId(chatId));
        }
    }

    /// <inheritdoc />
    public Task<Identity?> TransitionAsync(
        string userId,
        string? chatId,
        string? expected,
        string nextGeneration,
        CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _rows.TryGetValue(userId, out var current);

            // The expectation failed, so the stored row is left exactly as it was.
            // Returning null rather than throwing lets the caller decide whether this
            // is a conflict or a stale token.
            if (expected != Generations.Any && current?.Generation != expected)
            {
                return Task.FromResult<Identity?>(null);
            }

            if (chatId is not null)
            {
                var holder = ByChatId(chatId);

                if (holder is not null && holder.UserId != userId)
                {
                    throw new ChatAlreadyLinkedException(
                        "That Telegram chat is already the second factor for another account.");
                }
            }

            var identity = new Identity(
                userId,
                chatId,
                chatId is null ? null : _clock.Now,
                nextGeneration);

            _rows[userId] = identity;

            return Task.FromResult<Identity?>(identity);
        }
    }

    /// <summary>Seeds a verified enrollment without going through a flow.</summary>
    public void Seed(string userId, string? chatId, string generation)
    {
        lock (_gate)
        {
            _rows[userId] = new Identity(userId, chatId, _clock.Now, generation);
        }
    }

    /// <summary>Caller must hold the lock.</summary>
    private Identity? ByChatId(string chatId)
    {
        foreach (var row in _rows.Values)
        {
            if (!string.IsNullOrEmpty(row.ChatId) && row.ChatId == chatId)
            {
                return row;
            }
        }

        return null;
    }
}
