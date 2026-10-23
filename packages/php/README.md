# kampe/telegram-2fa

Telegram as a second authentication factor for PHP 8.1+. Framework-agnostic core,
with a Laravel adapter included and no required dependencies.

Implements [SPEC.md](../../SPEC.md) v1.0. The
[Node package](../node) in the same repository implements the same protocol, so
both can run against one bot and one database — see
`Stores\RedisCodeStore` for the adapter that makes that true in production.

```bash
composer require kampe/telegram-2fa
```

---

## Laravel

Auto-discovered. Publish, migrate, configure:

```bash
php artisan vendor:publish --tag=telegram-2fa-config
php artisan vendor:publish --tag=telegram-2fa-migrations
php artisan migrate

php artisan telegram:webhook --generate-secret   # → .env
php artisan telegram:webhook                     # register with Telegram
php artisan telegram:status                      # verify the wiring
```

```php
use Kampe\TelegramTwoFactor\Laravel\HasTelegramTwoFactor;

class User extends Authenticatable
{
    use HasTelegramTwoFactor;
}
```

```php
$link   = $user->startTelegramLink();                       // → ->url for a t.me button
$result = $user->completeTelegramLink($pastedCode);         // paste flow
$sent   = $user->sendTelegramCode('withdrawal');            // challenge
$check  = $user->verifyTelegramCode($code, 'withdrawal');   // verification
$moved  = $user->replaceTelegramChat($code);                // move to a new account
$gone   = $user->unlinkTelegram($code);                     // requires proof
```

Full controller, route and view code: [examples/laravel](../../examples/laravel).

---

## Any other framework

Construct the service with four adapters. Nothing below touches a framework.

```php
use Kampe\TelegramTwoFactor\{Config, TelegramTwoFactor};
use Kampe\TelegramTwoFactor\Telegram\{DefaultMessages, HttpTelegramClient};

$config = Config::fromArray([
    'bot_token' => getenv('TELEGRAM_BOT_TOKEN'),
    'bot_username' => getenv('TELEGRAM_BOT_USERNAME'),
    'webhook_secret' => getenv('TELEGRAM_WEBHOOK_SECRET'),
    'hash_pepper' => getenv('TELEGRAM_2FA_HASH_PEPPER'),
    'app_name' => 'Kampe',
]);

$tfa = new TelegramTwoFactor(
    $config,
    new MyRedisCodeStore($redis),     // Contracts\CodeStore     — 3 methods
    new MyUserIdentityStore($pdo),    // Contracts\IdentityStore — 4 methods
    new HttpTelegramClient($config->botToken),
    new DefaultMessages(),
);
```

`Config` validates on construction and throws `ConfigurationError` rather than
accepting a configuration that cannot be secure — a missing webhook secret, an
unlimited attempt budget, a code lifetime measured in days.

### The webhook

Two lines before anything else happens:

```php
use Kampe\TelegramTwoFactor\Webhook\{UpdateHandler, WebhookVerifier};

$verifier = new WebhookVerifier($config);

if (! $verifier->accepts($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? null)) {
    http_response_code(403);
    exit;
}

$handler = new UpdateHandler($tfa, $config, $store, $telegram, new DefaultMessages());
$handler->handle(json_decode(file_get_contents('php://input'), true) ?? []);

http_response_code(200);    // always 200 — see SPEC.md 7.5
echo '{"ok":true}';
```

Skipping the verifier makes the endpoint accept "this chat id is asking for a
code" from anyone who finds the URL. See
[SECURITY.md T1](../../SECURITY.md#t1--a-forged-webhook-request).

### Adding your own bot commands

```php
$handler->on('balance', function (string $chatId, string $argument) use ($telegram) {
    $telegram->sendMessage($chatId, 'Balance: ...');
});
```

---

## API

### Linking

| Method | Purpose |
| --- | --- |
| `startDeepLink(string $userId): LinkRequest` | Mint a nonce bound to the account; `->url` is the `t.me` link. |
| `completeDeepLink(string $token, string $chatId): LinkResult` | Resolve a `/start` payload. Single use. |
| `startPasteLink(string $chatId): LinkRequest` | Bot side: mint an 8-character code bound to the chat. |
| `completePasteLink(string $userId, string $code): LinkResult` | Authenticated page side. Rate-limit this. |
| `startChatReplacement(string $userId, string $code): LinkRequest\|VerificationResult` | Move to a new Telegram account, proving the old one first. |

### Challenge and verification

| Method | Purpose |
| --- | --- |
| `push(string $userId, string $purpose = 'login'): ChallengeResult` | Issue a code and send it. |
| `pull(string $chatId): ChallengeResult` | The user asked the bot for one; purpose `on_demand`. |
| `verify(string $userId, string $code, string $purpose = 'login'): VerificationResult` | Check a code. |

Neither challenge method returns the code, so both results are safe to serialise
into an HTTP response.

`$purpose` names the step a code authorises and is checked on every
verification. Pass the action's own name for anything privileged:

```php
$user->sendTelegramCode('withdrawal');
// ...
$user->verifyTelegramCode($code, 'withdrawal');   // a login code will not pass
```

There is no "match anything" value, and the default is `login` on both sides
rather than a wildcard. The constants are
`TelegramTwoFactor::PURPOSE_LOGIN`, `PURPOSE_ON_DEMAND`, `PURPOSE_REPLACE` and
`PURPOSE_UNLINK`; a code the user fetched with `/code` carries `on_demand` and
satisfies any purpose, which is what keeps `/code` usable for confirming an
unlink.

### State and removal

| Method | Purpose |
| --- | --- |
| `isLinked(string $userId): bool` | Verified link present. |
| `identity(string $userId): ?Identity` | The binding, if any. |
| `identityForChat(string $chatId): ?Identity` | Reverse lookup, for the webhook. |
| `unlink(string $userId, string $code): VerificationResult` | Remove, with proof under purpose `unlink`. |
| `unlinkAfterExternalProof(string $userId, string $reason): bool` | Remove, when another factor proved it. |

Errors are the `ErrorCode` enum, whose values are the protocol's shared strings
(`not_linked`, `cooldown`, `invalid`, …). `$error->message()` gives text safe to
show a user.

---

## Contracts

| Interface | Methods | Bundled implementations |
| --- | --- | --- |
| `CodeStore` | `get`, `put`, `forget`, `take`, `add` | `Stores\RedisCodeStore` (**use this one**), `Stores\ArrayCodeStore`, `Laravel\CacheCodeStore` (PHP-only) |
| `IdentityStore` | `findByUserId`, `findByChatId`, `transition` | `Stores\ArrayIdentityStore`, `Laravel\EloquentIdentityStore` |
| `TelegramClient` | `sendMessage`, `answerCallbackQuery`, `getMe`, `setWebhook`, `deleteWebhook` | `Telegram\HttpTelegramClient` (curl) |
| `Messages` | 11 string methods | `Telegram\DefaultMessages` (English) |
| `Clock` | `now` | `Support\SystemClock`, `Support\FrozenClock` |
| `Logger` | `info`, `warning`, `error` | `Support\NullLogger`, `Support\PsrLogger` |

`FrozenClock` ships in `src` rather than `tests` so your own suite can test
expiry and cooldown without sleeping through them.

---

## Configuration

Defaults are the recommended values; the bounds are enforced.

| Key | Default | Bounds |
| --- | --- | --- |
| `code_length` | 6 | 6–8 |
| `code_ttl` | 300 | 30–600 |
| `cooldown` | 120 | ≥ 30 |
| `max_attempts` | 5 | 1–10 |
| `link_code_length` | 8 | ≥ 8 |
| `link_ttl` | 600 | 60–900 |
| `webhook_secret` | — | 32–256 chars of `A-Za-z0-9_-`, required |
| `hash_pepper` | — | 32+ chars, **required** |
| `on_demand_satisfies` | `null` (any) | list of purposes, or null |
| `dedupe_updates` | `true` | — |
| `restrict_webhook_ips` | `false` | — |

---

### Why `take` and `add`

`CodeStore` asks for two atomic operations beyond the obvious three, and they
are not a convenience. Single use and the attempt budget are read-modify-write
sequences, so built from get-check-delete they race: two verifications arriving
together both read the live record, both match, and both succeed, while the
attempt counter loses increments to the same lost update.

`take` is an atomic get-and-delete — Redis `GETDEL`, Laravel `Cache::pull`,
`DELETE ... RETURNING`. `add` is an atomic set-if-absent that reports whether it
stored, which makes the cooldown and the webhook claim a reservation exactly one
caller can win.

### Two Redis adapters, and which to use

`Stores\RedisCodeStore` is the canonical one and what the service provider wires
by default. It talks to a Redis connection directly: values are the JSON of
[SPEC.md section 9](../../SPEC.md) and `take` is one server-side operation
(`GETDEL`, or `EVAL` of a GET-then-DEL script on servers before 6.2). That is
what lets this package share a Redis and a bot with the Node, Python, Ruby and C#
implementations.

```php
use Illuminate\Support\Facades\Redis;
use Kampe\TelegramTwoFactor\Laravel\LaravelRedisCommands;
use Kampe\TelegramTwoFactor\Stores\PhpRedisCommands;
use Kampe\TelegramTwoFactor\Stores\RedisCodeStore;

// Plain PHP, with ext-redis:
$store = new RedisCodeStore(new PhpRedisCommands($redis));

// Laravel, through the connection rather than the cache:
$store = new RedisCodeStore(new LaravelRedisCommands(Redis::connection()));
```

Any other client is four methods — implement `Contracts\RedisCommands`. The one
obligation the signature states and cannot enforce: `getDelete` must be a single
server round trip. A `GET` followed by a `DEL` satisfies the interface, passes
every single-threaded test, and races.

#### The connection still has options, and they matter

Using a connection instead of the cache removes the **cache's** serialization.
It does not remove the client's own, and it does not remove key prefixes. Three
settings will break interop, and the adapters check all three at construction
rather than letting them apply quietly:

| Setting | Effect | Verdict |
| --- | --- | --- |
| `options.prefix` | `tg2fa:code:u` is stored at `<prefix>tg2fa:code:u` | refused unless acknowledged |
| `options.serializer` | every value is wrapped before it reaches Redis | refused |
| `options.compression` | every value is deflated before it reaches Redis | refused |

The prefix one is the common case, not an exotic one: a default Laravel
application sets `options.prefix` from `REDIS_PREFIX`, which defaults to
`<app_name>_database_`. So out of the box a Laravel app would write
`laravel_database_tg2fa:code:user-1` while a Node process looks for
`tg2fa:code:user-1` and finds nothing.

Either give this package a connection with no prefix and namespace with
`Config::$keyPrefix` — which every implementation honours, because it is part of
the key the specification describes — or set
`telegram-2fa.allow_redis_key_prefix` if every client reading these keys applies
the same prefix. On a PHP-only deployment a prefix is harmless; it is the silence
that was the problem.

`Laravel\CacheCodeStore` is **PHP-only**, and was the default until a review
found out why that mattered:

- Laravel's Redis cache runs values through `serialize()`, so a record lands as
  `a:6:{s:4:"hash";...}` rather than JSON. The other implementations cannot read
  it and it cannot read theirs. The `/conformance` fixtures did not catch this,
  because they check a record's *shape* against an in-memory store rather than
  the bytes the production adapter puts on the wire — `tests/Integration/RedisInteropTest`
  now checks the bytes.
- Its `take` is serialised behind Laravel's named lock. That is a real guarantee
  between PHP processes and meaningless to a Node process issuing `GETDEL`, which
  never takes the lock, so the two can interleave over one code.

It stays because on a Laravel-only deployment the lock does hold across workers
and machines, and the cache abstraction lets it run on Memcached or DynamoDB. Opt
in with `telegram-2fa.code_store => 'cache'`.

Either way it does not use `Cache::pull()`. That helper reads like an atomic take
and is `get()` then `forget()` on every driver, so a verification built on it
races exactly as a hand-written pair would; an earlier revision of this package
was built on it and claimed otherwise in a comment.

`IdentityStore` has one mutating method for the same family of reasons: a
`link`/`unlink` pair invites read-then-write, and the window between validating
a replacement token and writing the binding is where that token outlives the
enrollment it proved. `transition()` takes the generation you expect and either
applies or changes nothing.

## Requirements

PHP 8.1 or newer. `ext-curl` for the bundled Telegram client; implement
`TelegramClient` yourself to avoid it.

A cache store with atomic get-and-delete and set-if-absent: `redis` or
`memcached`. See above for why this is a correctness requirement.

## Tests

```bash
composer install
composer test
```

150 tests written clause by clause against the specification:

- the cross-language fixtures in `/conformance`, which the Node package reads too
- `EloquentIdentityStoreTest` — the conditional transition and the unique index
  against a real SQL engine (SQLite in memory), which is what caught the store
  calling Laravel's global `now()` helper and dying wherever that helper is not
  autoloaded
- `CacheCodeStoreTest` — the Laravel adapter against real Illuminate stores
- `tests/Integration/RedisInteropTest` — against a live Redis, the bytes on the
  wire in both directions, plus eight real OS processes racing one key. This is
  the suite the `/conformance` fixtures could not be: they seed an in-memory
  store, so they pass whatever an adapter does to a value on its way to the
  server. CI **fails if it skips**
- `CodeStoreSelectionTest` — which store the service provider wires, because a
  correct adapter that nothing resolves by default changes nothing in production
- `tests/Integration/RedisCacheCodeStoreTest` — against a live Redis: the
  cross-instance lock, server-enforced expiry, and a whole challenge round trip
  over the wire. Skipped unless `REDIS_HOST` is set; CI provides one and **fails
  if the suite skips**, because a guarantee resting on a skipped test is not
  one. It never flushes — `Cache::clear()` on a Redis store is `FLUSHDB`, which
  would destroy the whole database rather than this suite's keys — so it is safe
  to point at a Redis you care about.
- `ConcurrencyTest` and `TransitionRaceTest` — interleavings, driven by
  deterministic hooks rather than sleeps

Each protection has been checked by removing it and confirming the matching test
fails.
