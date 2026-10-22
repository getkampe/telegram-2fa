# Kampe.TelegramTwoFactor

Telegram as a second authentication factor for .NET 8+. No package dependencies,
no framework assumptions.

Implements [SPEC.md](../../SPEC.md) v1.0, the same protocol as the
[PHP](../php) and [Node](../node) packages in this repository, so all of them
interoperate against one bot and one store.

```bash
dotnet add package Kampe.TelegramTwoFactor
```

---

## Wiring

```csharp
using Kampe.TelegramTwoFactor;
using Kampe.TelegramTwoFactor.Stores;
using Kampe.TelegramTwoFactor.Telegram;

var config = Config.FromEnvironment();      // or new Config(botToken, webhookSecret, hashPepper, ...)

var tfa = new TelegramTwoFactorService(
    config,
    new RedisCodeStore(redis),              // or MemoryCodeStore for tests
    new UserIdentityStore(db),              // 3 methods — the only adapter you write
    new HttpTelegramClient(config.BotToken, httpClient),
    new DefaultMessages());
```

In ASP.NET Core:

```csharp
builder.Services.AddSingleton(_ => Config.FromEnvironment());
builder.Services.AddHttpClient<HttpTelegramClient>();
builder.Services.AddSingleton<ICodeStore, RedisCodeStore>();
builder.Services.AddScoped<IIdentityStore, UserIdentityStore>();
builder.Services.AddSingleton<IMessages, DefaultMessages>();
builder.Services.AddScoped<TelegramTwoFactorService>();
```

`Config` validates in its constructor and throws `ConfigurationException` rather
than accepting something that cannot be secure: a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days.

`Config.FromEnvironment()` reads `TELEGRAM_BOT_TOKEN`, `TELEGRAM_BOT_USERNAME`,
`TELEGRAM_WEBHOOK_SECRET`, `TELEGRAM_2FA_HASH_PEPPER` and the optional
`TELEGRAM_2FA_CODE_TTL`, `_COOLDOWN`, `_MAX_ATTEMPTS`, `_APP_NAME`. Numbers are
parsed with `NumberStyles.None`, so `MAX_ATTEMPTS="5 attempts"` is a startup
failure rather than a silently wrong security parameter.

`TELEGRAM_2FA_HASH_PEPPER` is required and must be at least 32 characters: it is
the HMAC key for code hashes, and a six-digit code has only a million possible
values, so an unkeyed digest of one is reversed by a table anyone can build in
seconds.

### The identity store

Three methods over your own users table. In EF Core:

```csharp
public sealed class UserIdentityStore(AppDbContext db) : IIdentityStore
{
    public async Task<Identity?> FindByUserIdAsync(string userId, CancellationToken ct = default) =>
        // Returned even when no chat is linked: the generation outlives the
        // binding, so a token minted before an unlink stays void after a relink.
        ToIdentity(await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct));

    public async Task<Identity?> FindByChatIdAsync(string chatId, CancellationToken ct = default) =>
        ToIdentity(await db.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => u.TelegramChatId == chatId, ct));

    // The comparison is part of the write. Validating in application code and
    // then writing leaves a window in which a recovery can land and be silently
    // overwritten — which is how a replacement token outlives the enrollment it
    // proved.
    public async Task<Identity?> TransitionAsync(
        string userId, string? chatId, string? expected, string nextGeneration,
        CancellationToken ct = default)
    {
        var query = db.Users.Where(u => u.Id == userId);

        if (expected != Generations.Any)
        {
            query = query.Where(u => u.TelegramEnrollment == expected);
        }

        try
        {
            var updated = await query.ExecuteUpdateAsync(
                set => set
                    .SetProperty(u => u.TelegramChatId, chatId)
                    .SetProperty(u => u.TelegramLinkedAt, chatId is null ? null : DateTime.UtcNow)
                    .SetProperty(u => u.TelegramEnrollment, nextGeneration),
                ct);

            // Changed under us: nothing was written, and the caller decides
            // whether that is a conflict or a stale token.
            if (updated != 1)
            {
                return null;
            }
        }
        catch (DbUpdateException exception) when (IsUniqueViolation(exception))
        {
            // The unique index on TelegramChatId is what actually guarantees one
            // chat per account: two concurrent transitions both pass an
            // application check, and only one can pass the index.
            throw new ChatAlreadyLinkedException("That chat is already a second factor.");
        }

        return await FindByUserIdAsync(userId, ct);
    }

    private static Identity? ToIdentity(User? user) =>
        user is null
            ? null
            : new Identity(
                user.Id,
                user.TelegramChatId,
                user.TelegramLinkedAt is null
                    ? null
                    : new DateTimeOffset(user.TelegramLinkedAt.Value, TimeSpan.Zero).ToUnixTimeSeconds(),
                user.TelegramEnrollment);
}
```

The matching model:

```csharp
public sealed class User
{
    public string Id { get; set; } = "";
    public string? TelegramChatId { get; set; }        // unique index — load-bearing
    public DateTime? TelegramLinkedAt { get; set; }
    public string? TelegramEnrollment { get; set; }    // kept when unlinked, on purpose
}

// In OnModelCreating:
modelBuilder.Entity<User>().HasIndex(u => u.TelegramChatId).IsUnique();
```

### The webhook

```csharp
app.MapPost("/telegram/webhook", async (HttpContext http, UpdateHandler handler, WebhookVerifier verifier) =>
{
    var secret = http.Request.Headers[WebhookVerifier.SecretHeader].ToString();

    if (!verifier.Accepts(secret, http.Connection.RemoteIpAddress?.ToString()))
    {
        return Results.StatusCode(403);
    }

    using var reader = new StreamReader(http.Request.Body);
    var body = await reader.ReadToEndAsync();

    try
    {
        await handler.HandleJsonAsync(body);
    }
    catch (Exception exception)
    {
        // The failure, never the payload: the payload contains the codes.
        logger.LogError("telegram-2fa: handler failed: {Type}", exception.GetType().Name);
    }

    return Results.Ok(new { ok = true });   // always 200 — see SPEC.md 7.5
});
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

Adding your own commands:

```csharp
handler.On("balance", async (chatId, argument) =>
    await telegram.SendMessageAsync(chatId, $"Balance: {await BalanceFor(chatId)}"));
```

---

## API

Every method is async and takes an optional `CancellationToken`.

### Linking

| Method | Purpose |
| --- | --- |
| `StartDeepLinkAsync(userId)` | Mint a nonce bound to the account; `.Url` is the `t.me` link. |
| `CompleteDeepLinkAsync(token, chatId)` | Resolve a `/start` payload. Single use. |
| `StartPasteLinkAsync(chatId)` | Bot side: mint an 8-character code bound to the chat. |
| `CompletePasteLinkAsync(userId, code)` | Authenticated page side. Rate-limit this. |
| `StartChatReplacementAsync(userId, code)` | Move to a new Telegram account, proving the old one first. |

`StartChatReplacementAsync` returns a `ReplacementResult`: check `.Ok`, then read
`.Request`. One type rather than a union, so a caller cannot reach the token
without having checked.

### Challenge and verification

| Method | Purpose |
| --- | --- |
| `PushAsync(userId, purpose = Purpose.Login)` | Issue a code and send it. |
| `PullAsync(chatId)` | The user asked the bot for one; purpose `on_demand`. |
| `VerifyAsync(userId, code, purpose = Purpose.Login)` | Check a code. |

Neither challenge method returns the code, so both results are safe to serialise
into a response.

`purpose` names the step a code authorises and is checked on every verification:

```csharp
await tfa.PushAsync(user.Id, "withdrawal");
// ...
await tfa.VerifyAsync(user.Id, code, "withdrawal");   // a login code will not pass
```

There is no "match anything" value, and the default is `login` on both sides
rather than a wildcard. Constants: `Purpose.Login`, `Purpose.OnDemand`,
`Purpose.Replace`, `Purpose.Unlink`. A code the user fetched with `/code` carries
`on_demand` and satisfies any purpose, which is what keeps `/code` usable for
confirming an unlink; narrow that with `onDemandSatisfies`.

### State and removal

| Method | Purpose |
| --- | --- |
| `IsLinkedAsync(userId)` | Verified link present. |
| `IdentityAsync(userId)` / `IdentityForChatAsync(chatId)` | The binding, either direction. |
| `UnlinkAsync(userId, code)` | Remove, with proof under purpose `unlink`. |
| `UnlinkAfterExternalProofAsync(userId, reason)` | Remove, when another factor proved it. |

`result.Error` on a failure is one of the protocol's shared strings
(`ErrorCode.NotLinked`, `Cooldown`, `Invalid`, …) and `result.Message` is text
safe to show a user.

---

## What the package gives you

| Type | What it is |
| --- | --- |
| `TelegramTwoFactorService` | The protocol. |
| `Config` | Validated configuration, plus `FromEnvironment` and `GenerateSecret`. |
| `MemoryCodeStore`, `MemoryIdentityStore` | In-process, for tests. |
| `RedisCodeStore`, `IRedisCommands` | Redis, through a four-method adapter you write. |
| `HttpTelegramClient` | Telegram over `HttpClient`, plus `SetWebhookAsync`. |
| `DefaultMessages`, `Html.Escape` | Bot copy, and the escaper to use if you write your own. |
| `WebhookVerifier` | Webhook authentication, including `SecretHeader` and the IP ranges. |
| `UpdateHandler`, `TelegramUpdate` | Command dispatch, and the update model. |
| `CodeGenerator`, `CodeHasher` | CSPRNG codes; HMAC plus `FixedTimeEquals`. |
| `SystemClock`, `FrozenClock` | A clock you control, for testing expiry without sleeping. |
| `Identity`, `Generations.Any` | The binding, and the "skip the comparison" sentinel. |
| `IEventLog`, `DelegateEventLog` | Logging, without a dependency on any logging package. |

### The Redis adapter

`IRedisCommands` is four methods, so the package needs no Redis dependency. With
StackExchange.Redis:

```csharp
public sealed class StackExchangeRedisCommands(IDatabase db) : IRedisCommands
{
    public async Task<string?> GetAsync(string key, CancellationToken ct) =>
        await db.StringGetAsync(key);

    public Task DeleteAsync(string key, CancellationToken ct) =>
        db.KeyDeleteAsync(key);

    public Task<bool> SetAsync(string key, string value, int ttlSeconds, bool onlyIfAbsent, CancellationToken ct) =>
        db.StringSetAsync(
            key, value, TimeSpan.FromSeconds(ttlSeconds),
            when: onlyIfAbsent ? When.NotExists : When.Always);

    // GETDEL on Redis 6.2+. On an older server, run a GET-then-DEL script with
    // ScriptEvaluateAsync — never a GET followed by a DEL from here.
    public async Task<string?> GetDeleteAsync(string key, CancellationToken ct) =>
        await db.StringGetDeleteAsync(key);
}
```

---

## Testing against it

```csharp
var clock = new FrozenClock();

var tfa = new TelegramTwoFactorService(
    config,
    new MemoryCodeStore(clock),
    new MemoryIdentityStore(clock),
    fakeClient,                      // record what it was asked to send
    new DefaultMessages(),
    clock);

await tfa.PushAsync("user-1");
clock.Advance(301);
// → expired, with no waiting
```

Because the library never returns the code, read it back out of the message your
fake captured — which is also a neat proof that it is not leaking anywhere else.

---

### Why `ICodeStore` has five methods

`TakeAsync` and `AddAsync` are not a convenience. Single use and the attempt
budget are read-modify-write sequences, so built from get-check-delete they race:
two verifications arriving together both read the live record, both match, and
both succeed, while the attempt counter loses increments to the same lost update.

`TakeAsync` is an atomic get-and-delete (Redis `GETDEL`, or `EVAL` on older
servers); `AddAsync` is an atomic set-if-absent that reports whether it stored,
which makes the cooldown and the webhook's idempotency claim a reservation
exactly one caller can win.

`IRedisCommands` requires `GetDeleteAsync`, so an adapter that cannot do it in
one round trip will not compile. The other implementations of this protocol have
to probe a duck-typed client at construction and throw when it offers no atomic
primitive; here the unsafe shape is unreachable rather than merely rejected.

`IIdentityStore` has one mutating method, `TransitionAsync`, for a related
reason: a link/unlink pair invites read-then-write, and the window between
validating a replacement token and writing the binding is where that token
outlives the enrollment it proved. Hand the store the generation you expect and
let it decide.

### On async and critical sections

Every store call in the service is awaited, and no lock is ever held across one.
That is not an accident of style: in an event loop an `await` inside a critical
section is a suspension point, which is how the Node port once let two concurrent
verifications of a single code both succeed. Here the atomicity lives entirely in
the store's own primitives, so there is no critical section for an `await` to
split — and C# helps, because the compiler refuses an `await` inside a `lock`.

## Requirements

.NET 8 or newer. Only the base class library: `System.Security.Cryptography`,
`System.Text.Json`, `System.Net.Http`.

A store with atomic get-and-delete and set-if-absent. Redis 6.2+ has `GETDEL`;
older servers are handled through `EVAL` in your adapter.

## Tests

```bash
dotnet test
```

126 tests written clause by clause against the specification, including the
cross-language fixtures in `/conformance` that the other packages also read, and
real-thread concurrency tests against the shipped stores.

Making those race tests actually sensitive took two different devices, because
the two windows that matter are in different places:

- **Inside a critical section.** A `YieldingClock` that sleeps whenever it is
  read. Without it the store tests pass against a store with no lock at all,
  because a critical section this short completes before the scheduler preempts
  it — the false confidence a race test must not give.
- **Between two store calls.** A clock cannot open this one: a pause inside a
  critical section is harmless, and the thread that released a lock can
  re-acquire it before a woken waiter is scheduled, so a service built from
  get-then-delete still looks atomic. `AtomicConsumptionTests` wraps the store so
  it yields after each call returns, and asserts outright that a verification
  consumes its record in a single operation.

The races use dedicated `Thread`s rather than `Task.Run`, because the thread pool
injects new threads slowly and a barrier across more tasks than it currently has
would stall for seconds before the race even started.

Each protection has been checked by removing it and confirming the matching test
fails.
