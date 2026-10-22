using System.Text.RegularExpressions;
using Kampe.TelegramTwoFactor.Stores;
using Kampe.TelegramTwoFactor.Telegram;

namespace Kampe.TelegramTwoFactor.Tests;

/// <summary>Records what it was asked to send.</summary>
public sealed class FakeTelegram : ITelegramClient
{
    private readonly List<(string ChatId, string Text)> _sent = new();
    private readonly List<string> _answered = new();
    private readonly object _gate = new();
    private Func<Task>? _duringNextFailure;

    public bool ShouldFailSending { get; set; }

    public IReadOnlyList<(string ChatId, string Text)> Sent
    {
        get
        {
            lock (_gate)
            {
                return _sent.ToArray();
            }
        }
    }

    public IReadOnlyList<string> Answered
    {
        get
        {
            lock (_gate)
            {
                return _answered.ToArray();
            }
        }
    }

    public string LastMessage
    {
        get
        {
            lock (_gate)
            {
                return _sent.Count == 0 ? string.Empty : _sent[^1].Text;
            }
        }
    }

    public string? LastSentTo
    {
        get
        {
            lock (_gate)
            {
                return _sent.Count == 0 ? null : _sent[^1].ChatId;
            }
        }
    }

    /// <summary>
    /// Fails the next send, running <paramref name="during"/> while it is "in
    /// flight".
    /// </summary>
    /// <remarks>
    /// Models a send that blocks long enough for the world to move on - the cooldown
    /// lapsing and another challenge being issued - before the failure is reported
    /// and its cleanup runs.
    /// </remarks>
    public void FailNextSend(Func<Task> during)
    {
        ShouldFailSending = true;
        _duringNextFailure = during;
    }

    public async Task<bool> SendMessageAsync(
        string chatId,
        string text,
        IReadOnlyList<IReadOnlyList<(string Text, string Data)>>? inlineKeyboard = null,
        CancellationToken cancellationToken = default)
    {
        if (ShouldFailSending)
        {
            if (_duringNextFailure is not null)
            {
                // One-shot: the hook models a single slow, failing send, and the sends
                // it triggers must succeed.
                var during = _duringNextFailure;
                _duringNextFailure = null;
                ShouldFailSending = false;

                await during().ConfigureAwait(false);
            }

            return false;
        }

        lock (_gate)
        {
            _sent.Add((chatId, text));
        }

        return true;
    }

    public Task<bool> AnswerCallbackQueryAsync(
        string callbackQueryId,
        string? text = null,
        CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _answered.Add(callbackQueryId);
        }

        return Task.FromResult(true);
    }

    public void Reset()
    {
        lock (_gate)
        {
            _sent.Clear();
            _answered.Clear();
        }
    }
}

/// <summary>
/// A clock that yields the scheduler whenever it is read.
/// </summary>
/// <remarks>
/// Threads alone are not always enough to expose a missing lock: a critical
/// section this short usually completes before the scheduler preempts it, so an
/// unsynchronised implementation passes a threaded test most of the time. That is
/// exactly the false confidence a race test must not give.
/// <para>
/// The store reads the clock between looking a record up and removing it, so
/// sleeping here forces the interleaving. With the lock held the sleep is harmless
/// - other threads simply wait for it - and without the lock a second thread reads
/// the record the first is about to delete.
/// </para>
/// </remarks>
public sealed class YieldingClock : IClock
{
    private readonly int _pauseMs;
    private long _now;

    public YieldingClock(long now = 1_700_000_000, int pauseMs = 5)
    {
        _now = now;
        _pauseMs = pauseMs;
    }

    public long Now
    {
        get
        {
            Thread.Sleep(_pauseMs);

            return Interlocked.Read(ref _now);
        }
    }

    public YieldingClock Advance(long seconds)
    {
        Interlocked.Add(ref _now, seconds);

        return this;
    }
}

/// <summary>
/// Wraps a store, recording every call and yielding the scheduler after each one
/// returns.
/// </summary>
/// <remarks>
/// This opens a window the shipped store cannot be made to open: a pause
/// <em>inside</em> a critical section is harmless, and the thread that released a
/// lock can re-acquire it before a woken waiter is scheduled, so a service built
/// from get-then-delete still looks atomic under a yielding clock. The gap that
/// matters is between two store calls, which is here.
/// <para>
/// The call log is the deterministic half of the same check: a verification that
/// consumes its record in one operation can only be a take.
/// </para>
/// </remarks>
public sealed class RecordingStore : ICodeStore
{
    private readonly ICodeStore _inner;
    private readonly int _pauseMs;
    private readonly List<string> _calls = new();
    private readonly object _gate = new();

    public RecordingStore(ICodeStore inner, int pauseMs = 2)
    {
        _inner = inner;
        _pauseMs = pauseMs;
    }

    public IReadOnlyList<string> Calls
    {
        get
        {
            lock (_gate)
            {
                return _calls.ToArray();
            }
        }
    }

    public void ResetCalls()
    {
        lock (_gate)
        {
            _calls.Clear();
        }
    }

    public async Task<string?> GetAsync(string key, CancellationToken cancellationToken = default) =>
        await Record("get", () => _inner.GetAsync(key, cancellationToken)).ConfigureAwait(false);

    public async Task PutAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default) =>
        await Record<object?>("put", async () =>
        {
            await _inner.PutAsync(key, value, ttlSeconds, cancellationToken).ConfigureAwait(false);

            return null;
        }).ConfigureAwait(false);

    public async Task ForgetAsync(string key, CancellationToken cancellationToken = default) =>
        await Record<object?>("forget", async () =>
        {
            await _inner.ForgetAsync(key, cancellationToken).ConfigureAwait(false);

            return null;
        }).ConfigureAwait(false);

    public async Task<string?> TakeAsync(string key, CancellationToken cancellationToken = default) =>
        await Record("take", () => _inner.TakeAsync(key, cancellationToken)).ConfigureAwait(false);

    public async Task<bool> AddAsync(string key, string value, int ttlSeconds, CancellationToken cancellationToken = default) =>
        await Record("add", () => _inner.AddAsync(key, value, ttlSeconds, cancellationToken)).ConfigureAwait(false);

    private async Task<T> Record<T>(string name, Func<Task<T>> operation)
    {
        lock (_gate)
        {
            _calls.Add(name);
        }

        var result = await operation().ConfigureAwait(false);

        if (_pauseMs > 0)
        {
            Thread.Sleep(_pauseMs);
        }

        return result;
    }
}

public static class TestSupport
{
    public const string Secret = "ssssssssssssssssssssssssssssssssssssssssssssssss";

    private static readonly Regex CodePattern = new("<code>([^<]+)</code>", RegexOptions.Compiled);

    public static Config MakeConfig(
        string? botToken = null,
        string? webhookSecret = null,
        string? hashPepper = null,
        string? botUsername = "kampe_test_bot",
        string appName = "Kampe",
        int codeLength = 6,
        int codeTtl = 300,
        int cooldown = 120,
        int maxAttempts = 5,
        int linkCodeLength = 8,
        int linkTtl = 600,
        string keyPrefix = "tg2fa",
        string hashAlgorithm = "sha256",
        bool dedupeUpdates = true,
        int updateDedupeTtl = 3600,
        bool restrictWebhookIps = false,
        IReadOnlyList<string>? onDemandSatisfies = null) =>
        new(
            botToken ?? "123456789:AAFakeTokenForTestsOnly_0123456789abc",
            webhookSecret ?? Secret,
            hashPepper ?? "pppppppppppppppppppppppppppppppppppppppppppppppp",
            botUsername,
            appName,
            codeLength,
            codeTtl,
            cooldown,
            maxAttempts,
            linkCodeLength,
            linkTtl,
            keyPrefix,
            hashAlgorithm,
            dedupeUpdates,
            updateDedupeTtl,
            restrictWebhookIps,
            onDemandSatisfies);

    public static string CodeFrom(string message)
    {
        var match = CodePattern.Match(message);

        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    public static string WrongCode(string code) => code == "000000" ? "111111" : "000000";

    /// <summary>
    /// Runs <paramref name="count"/> operations on dedicated threads, released
    /// simultaneously.
    /// </summary>
    /// <remarks>
    /// Real threads rather than Task.Run: the thread pool injects new threads
    /// slowly, so a barrier across more tasks than it currently has would stall for
    /// seconds before the race even started. And the barrier is what makes this
    /// deterministic - without it the first operation usually finishes before the
    /// last one begins, and the test would pass against a broken implementation most
    /// of the time.
    /// </remarks>
    public static T[] Race<T>(int count, Func<int, Task<T>> body)
    {
        using var barrier = new Barrier(count);

        var results = new T[count];
        var failures = new Exception?[count];
        var threads = new Thread[count];

        for (var i = 0; i < count; i++)
        {
            var index = i;

            threads[i] = new Thread(() =>
            {
                barrier.SignalAndWait();

                try
                {
                    results[index] = body(index).GetAwaiter().GetResult();
                }
                catch (Exception exception)
                {
                    failures[index] = exception;
                }
            })
            {
                IsBackground = true,
            };
        }

        foreach (var thread in threads)
        {
            thread.Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        foreach (var failure in failures)
        {
            if (failure is not null)
            {
                throw failure;
            }
        }

        return results;
    }

    /// <summary>As <see cref="Race{T}"/>, but keeping each thread's exception.</summary>
    public static (T? Result, Exception? Failure)[] RaceTolerantly<T>(int count, Func<int, Task<T>> body)
    {
        using var barrier = new Barrier(count);

        var outcomes = new (T?, Exception?)[count];
        var threads = new Thread[count];

        for (var i = 0; i < count; i++)
        {
            var index = i;

            threads[i] = new Thread(() =>
            {
                barrier.SignalAndWait();

                try
                {
                    outcomes[index] = (body(index).GetAwaiter().GetResult(), null);
                }
                catch (Exception exception)
                {
                    outcomes[index] = (default, exception);
                }
            })
            {
                IsBackground = true,
            };
        }

        foreach (var thread in threads)
        {
            thread.Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        return outcomes;
    }
}

/// <summary>A fully wired service on in-memory parts.</summary>
public class Harness
{
    public Harness(IClock? clock = null, Config? config = null, ICodeStore? store = null)
    {
        Clock = clock ?? new FrozenClock();
        Store = store ?? new MemoryCodeStore(Clock);
        Identities = new MemoryIdentityStore(Clock);
        Telegram = new FakeTelegram();
        Config = config ?? TestSupport.MakeConfig();
        Messages = new DefaultMessages();

        Service = new TelegramTwoFactorService(
            Config, Store, Identities, Telegram, Messages, Clock);
    }

    public IClock Clock { get; }

    public ICodeStore Store { get; }

    public MemoryIdentityStore Identities { get; }

    public FakeTelegram Telegram { get; }

    public Config Config { get; }

    public IMessages Messages { get; }

    public TelegramTwoFactorService Service { get; }

    /// <summary>A service wired to the same parts but a different configuration.</summary>
    public TelegramTwoFactorService WithConfig(Config config) =>
        new(config, Store, Identities, Telegram, Messages, Clock);

    /// <summary>A service wired to the same parts but a different store.</summary>
    public TelegramTwoFactorService WithStore(ICodeStore store) =>
        new(Config, store, Identities, Telegram, Messages, Clock);

    /// <summary>Seeds a verified enrollment without going through a link flow.</summary>
    public void Seed(string userId = "user-1", string chatId = "555000111") =>
        Identities.Seed(userId, chatId, $"gen-{userId}");

    /// <summary>
    /// The code from the most recent outgoing message.
    /// </summary>
    /// <remarks>
    /// Tests have to recover it from the message because the library deliberately
    /// never returns it - which is also a neat proof that it is not leaking anywhere
    /// else.
    /// </remarks>
    public string LastCode => TestSupport.CodeFrom(Telegram.LastMessage);
}
